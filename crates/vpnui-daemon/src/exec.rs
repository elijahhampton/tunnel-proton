//! Running system tools: absolute paths only, argument arrays only, a cleared environment, a
//! timeout, and kill-on-drop. Nothing here goes through a shell.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_OUTPUT: usize = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    #[error("{program} is not an absolute path")]
    NotAbsolute { program: String },
    #[error("{program}: {source}")]
    Spawn {
        program: String,
        source: std::io::Error,
    },
    #[error("{program} timed out after {secs}s")]
    Timeout { program: String, secs: u64 },
    #[error("{program} exited with {status}: {stderr}")]
    Failed {
        program: String,
        status: ExitStatus,
        stderr: String,
    },
}

#[derive(Debug)]
pub struct Output {
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn combined(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }
}

/// A child that is killed and reaped if it is dropped while running.
pub struct Guarded(Option<Child>);

impl Guarded {
    pub fn new(child: Child) -> Self {
        Self(Some(child))
    }

    pub fn child(&mut self) -> Option<&mut Child> {
        self.0.as_mut()
    }

    pub fn id(&self) -> Option<u32> {
        self.0.as_ref().map(Child::id)
    }

    pub fn take(&mut self) -> Option<Child> {
        self.0.take()
    }
}

impl Drop for Guarded {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take()
            && matches!(child.try_wait(), Ok(None))
        {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

pub struct Cmd {
    program: &'static str,
    args: Vec<OsString>,
    env: Vec<(&'static str, OsString)>,
    stdin: Option<Zeroizing<Vec<u8>>>,
    timeout: Duration,
}

impl Cmd {
    pub fn new(program: &'static str) -> Self {
        Self {
            program,
            args: Vec::new(),
            env: Vec::new(),
            stdin: None,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    pub fn env(mut self, key: &'static str, value: impl Into<OsString>) -> Self {
        self.env.push((key, value.into()));
        self
    }

    pub fn stdin(mut self, bytes: Zeroizing<Vec<u8>>) -> Self {
        self.stdin = Some(bytes);
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Runs to completion. A non-zero exit is an error carrying stderr.
    pub fn run(self) -> Result<Output, ExecError> {
        let program = self.program;
        let output = self.output()?;
        if output.status.success() {
            Ok(output)
        } else {
            Err(ExecError::Failed {
                program: program.to_owned(),
                status: output.status,
                stderr: output.stderr.trim().to_owned(),
            })
        }
    }

    /// Runs to completion and returns the output whatever the exit status.
    pub fn output(self) -> Result<Output, ExecError> {
        if !Path::new(self.program).is_absolute() {
            return Err(ExecError::NotAbsolute {
                program: self.program.to_owned(),
            });
        }
        let mut command = Command::new(self.program);
        command
            .args(&self.args)
            .env_clear()
            .envs(self.env.iter().map(|(k, v)| (k, v)))
            .stdin(if self.stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = command.spawn().map_err(|source| ExecError::Spawn {
            program: self.program.to_owned(),
            source,
        })?;
        let mut guarded = Guarded::new(child);
        let Some(child) = guarded.child() else {
            return Err(ExecError::Timeout {
                program: self.program.to_owned(),
                secs: 0,
            });
        };

        let writer = match (child.stdin.take(), self.stdin) {
            (Some(mut pipe), Some(bytes)) => Some(thread::spawn(move || {
                let _ = pipe.write_all(&bytes);
            })),
            (Some(_) | None, Some(_) | None) => None,
        };
        let stdout = child.stdout.take().map(reader);
        let stderr = child.stderr.take().map(reader);

        let deadline = Instant::now() + self.timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() >= deadline => {
                    return Err(ExecError::Timeout {
                        program: self.program.to_owned(),
                        secs: self.timeout.as_secs(),
                    });
                }
                Ok(None) => thread::sleep(Duration::from_millis(5)),
                Err(source) => {
                    return Err(ExecError::Spawn {
                        program: self.program.to_owned(),
                        source,
                    });
                }
            }
        };
        guarded.take();
        if let Some(writer) = writer {
            let _ = writer.join();
        }
        let collect = |h: Option<thread::JoinHandle<Vec<u8>>>| {
            h.and_then(|h| h.join().ok())
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default()
        };
        Ok(Output {
            status,
            stdout: collect(stdout),
            stderr: collect(stderr),
        })
    }
}

fn reader<R: Read + Send + 'static>(mut pipe: R) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = (&mut pipe).take(MAX_OUTPUT as u64).read_to_end(&mut buf);
        buf
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_relative_programs() {
        assert!(matches!(
            Cmd::new("ls").run(),
            Err(ExecError::NotAbsolute { .. })
        ));
    }

    #[test]
    fn runs_with_args_stdin_and_cleared_env() {
        let out = Cmd::new("/bin/cat")
            .stdin(Zeroizing::new(b"hello".to_vec()))
            .run()
            .unwrap();
        assert_eq!(out.stdout, "hello");

        let env = Cmd::new("/usr/bin/env").env("ONLY", "this").run().unwrap();
        assert_eq!(env.stdout.trim(), "ONLY=this", "environment is cleared");

        let args = Cmd::new("/bin/echo")
            .args(["a b", "$HOME", ";", "c"])
            .run()
            .unwrap();
        assert_eq!(
            args.stdout, "a b $HOME ; c\n",
            "arguments reach argv literally"
        );
    }

    #[test]
    fn reports_failure_and_timeout() {
        assert!(matches!(
            Cmd::new("/usr/bin/false").run(),
            Err(ExecError::Failed { .. })
        ));
        let started = Instant::now();
        let slow = Cmd::new("/bin/sleep")
            .arg("5")
            .timeout(Duration::from_millis(200))
            .run();
        assert!(matches!(slow, Err(ExecError::Timeout { .. })));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "child was killed"
        );
    }
}

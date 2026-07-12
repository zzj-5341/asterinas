// SPDX-License-Identifier: MPL-2.0

//! Task sets.

use ostd::{
    sync::Waker,
    task::{CurrentTask, Task},
};

use crate::prelude::*;

/// A task set that maintains all tasks in a POSIX process.
pub struct TaskSet {
    tasks: Vec<Arc<Task>>,
    has_exited_main: bool,
    has_exited_group: bool,
    execve_phase: ExecvePhase,
    execve_waker: Option<Arc<Waker>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecvePhase {
    Idle,
    Preparing,
    Committing,
}

impl TaskSet {
    /// Creates a new task set.
    pub(super) fn new() -> Self {
        Self {
            tasks: Vec::new(),
            has_exited_main: false,
            has_exited_group: false,
            execve_phase: ExecvePhase::Idle,
            execve_waker: None,
        }
    }

    /// Inserts a new task to the task set.
    ///
    /// This method will fail after a group exit or an exec attempt starts.
    pub(super) fn insert(&mut self, task: Arc<Task>) -> Result<(), Arc<Task>> {
        if self.has_exited_group || self.execve_phase != ExecvePhase::Idle {
            return Err(task);
        }

        self.tasks.push(task);
        Ok(())
    }

    /// Removes the exited task from the task set if necessary.
    ///
    /// The task will be removed from the task set if the corresponding thread is not the main
    /// thread.
    ///
    /// This method will return true if there are no more alive tasks in the task set.
    ///
    /// # Panics
    ///
    /// This method will panic if the task is not in the task set.
    pub(super) fn remove_exited(&mut self, task: &CurrentTask) -> bool {
        let position = self
            .tasks
            .iter()
            .position(|some_task| core::ptr::eq(some_task.as_ref(), task.as_ref()))
            .unwrap();

        if position == 0 {
            assert!(!self.has_exited_main);
            self.has_exited_main = true;
        } else {
            self.tasks.swap_remove(position);
        }

        if let Some(waker) = self.execve_waker.as_ref() {
            waker.wake_up();
        }

        self.has_exited_main && self.tasks.len() == 1
    }

    /// Return whether the main thread has exited.
    pub(super) fn has_exited_main(&self) -> bool {
        self.has_exited_main
    }

    /// Removes the main task and makes the remaining task become the main task.
    ///
    /// The method should only be calling when doing execve.
    pub(super) fn swap_main(&mut self) {
        // This is an extremely internal method. The caller must uphold certain invariants, update
        // the thread status, modify the PID table entry, etc.

        self.tasks.swap_remove(0);
        self.has_exited_main = false;
    }

    /// Sets a flag that denotes that an `exit_group` has been initiated.
    pub(super) fn set_exited_group(&mut self) {
        debug_assert_ne!(self.execve_phase, ExecvePhase::Committing);
        self.has_exited_group = true;
    }

    /// Returns whether an `exit_group` has been initiated.
    pub(super) fn has_exited_group(&self) -> bool {
        self.has_exited_group
    }

    /// Starts the recoverable preparation phase of an `execve()` call.
    pub(super) fn start_execve_attempt(&mut self) {
        debug_assert!(!self.has_exited_group);
        debug_assert_eq!(self.execve_phase, ExecvePhase::Idle);
        self.execve_phase = ExecvePhase::Preparing;
    }

    /// Enters the no-return phase of an `execve()` call.
    pub(super) fn start_execve_commit(&mut self) {
        debug_assert!(!self.has_exited_group);
        debug_assert_eq!(self.execve_phase, ExecvePhase::Preparing);
        self.execve_phase = ExecvePhase::Committing;
    }

    /// Finishes an `execve()` call.
    pub(super) fn finish_execve(&mut self) {
        debug_assert_ne!(self.execve_phase, ExecvePhase::Idle);
        self.execve_phase = ExecvePhase::Idle;
    }

    /// Returns whether an `execve()` call is in progress.
    pub(super) fn execve_in_progress(&self) -> bool {
        self.execve_phase != ExecvePhase::Idle
    }

    /// Returns whether an `execve()` call is in its no-return phase.
    pub(super) fn in_execve(&self) -> bool {
        self.execve_phase == ExecvePhase::Committing
    }

    /// Registers a waker to be notified when any thread exits.
    ///
    /// Only a thread performing execve should set this waker; it is used to
    /// wake the execve-ing thread while it waits for other threads to exit.
    pub(super) fn set_execve_waker(&mut self, waker: Arc<Waker>) {
        debug_assert!(self.execve_waker.is_none());
        self.execve_waker = Some(waker);
    }

    /// Clears the waker previously set by [`Self::set_execve_waker`].
    pub(super) fn clear_execve_waker(&mut self) {
        self.execve_waker = None;
    }
}

impl TaskSet {
    /// Returns a slice of the tasks in the task set.
    pub fn as_slice(&self) -> &[Arc<Task>] {
        self.tasks.as_slice()
    }

    /// Returns the main task/thread.
    pub fn main(&self) -> &Arc<Task> {
        &self.tasks[0]
    }
}

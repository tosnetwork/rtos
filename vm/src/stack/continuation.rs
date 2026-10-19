/*
 * RTOS project modifications (2026-10-10): project and crate naming.
 * RTOS project modifications (2026-10-19): full child continuations for loop, envelope and
 * PushInt kinds; iterative cleanup and comparison of nested continuation graphs.
 * Copyright (C) 2019-2024 EverX. All Rights Reserved.
 * Modifications Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This file has been modified from its original version.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::stack::{savelist::SaveList, SliceData, Stack, StackItem};
use rtos_block::{error, Cell, ExceptionCode, Result};
use std::{collections::HashSet, fmt, mem, sync::Arc};

/// Kind of a continuation.
///
/// Only `Ordinary` and `Envelope` carry control data (the `nargs`, `stack` and `savelist`
/// fields of [`ContinuationData`]). For every other kind those fields stay empty; writing
/// control data onto such a continuation wraps it into an `Envelope` first
/// (see [`ContinuationData::force_cdata`]).
#[derive(Clone, Default)]
pub enum ContinuationType {
    /// Plain code continuation (code page 0).
    #[default]
    Ordinary,
    /// Control data around another continuation: applying it restores the saved registers and
    /// then continues with `next`.
    Envelope(Arc<ContinuationData>),
    /// Pushes a small integer, then continues with `next`.
    PushInt(i32, Arc<ContinuationData>),
    /// Terminates the VM with the given exit code.
    Quit(i32),
    /// Default exception handler: terminates with the exception number on the stack.
    ExcQuit,
    /// Loop continuation of REPEAT: `count` more iterations of `body`, then `after`.
    Repeat { count: i64, body: Arc<ContinuationData>, after: Arc<ContinuationData> },
    /// Loop continuation of AGAIN.
    Again { body: Arc<ContinuationData> },
    /// Loop continuation of UNTIL: checks the condition left by `body`.
    Until { body: Arc<ContinuationData>, after: Arc<ContinuationData> },
    /// Loop continuation of WHILE: `check_cond` is true after the condition ran.
    While {
        check_cond: bool,
        cond: Arc<ContinuationData>,
        body: Arc<ContinuationData>,
        after: Arc<ContinuationData>,
    },
}

impl ContinuationType {
    fn children(&self) -> Vec<&Arc<ContinuationData>> {
        match self {
            ContinuationType::Ordinary | ContinuationType::Quit(_) | ContinuationType::ExcQuit => {
                vec![]
            }
            ContinuationType::Envelope(next) | ContinuationType::PushInt(_, next) => vec![next],
            ContinuationType::Repeat { body, after, .. }
            | ContinuationType::Until { body, after } => vec![body, after],
            ContinuationType::Again { body } => vec![body],
            ContinuationType::While { cond, body, after, .. } => vec![cond, body, after],
        }
    }

    /// Moves every child continuation out as a stack item, leaving `Ordinary` behind.
    fn take_children(&mut self, out: &mut Vec<StackItem>) {
        match mem::take(self) {
            ContinuationType::Ordinary | ContinuationType::Quit(_) | ContinuationType::ExcQuit => {}
            ContinuationType::Envelope(next) | ContinuationType::PushInt(_, next) => {
                out.push(StackItem::Continuation(next))
            }
            ContinuationType::Repeat { body, after, .. }
            | ContinuationType::Until { body, after } => {
                out.push(StackItem::Continuation(body));
                out.push(StackItem::Continuation(after));
            }
            ContinuationType::Again { body } => out.push(StackItem::Continuation(body)),
            ContinuationType::While { cond, body, after, .. } => {
                out.push(StackItem::Continuation(cond));
                out.push(StackItem::Continuation(body));
                out.push(StackItem::Continuation(after));
            }
        }
    }

    fn same_shape(&self, other: &Self) -> bool {
        match (self, other) {
            (ContinuationType::Ordinary, ContinuationType::Ordinary)
            | (ContinuationType::ExcQuit, ContinuationType::ExcQuit)
            | (ContinuationType::Envelope(_), ContinuationType::Envelope(_))
            | (ContinuationType::Again { .. }, ContinuationType::Again { .. })
            | (ContinuationType::Until { .. }, ContinuationType::Until { .. }) => true,
            (ContinuationType::PushInt(a, _), ContinuationType::PushInt(b, _)) => a == b,
            (ContinuationType::Quit(a), ContinuationType::Quit(b)) => a == b,
            (
                ContinuationType::Repeat { count: a, .. },
                ContinuationType::Repeat { count: b, .. },
            ) => a == b,
            (
                ContinuationType::While { check_cond: a, .. },
                ContinuationType::While { check_cond: b, .. },
            ) => a == b,
            _ => false,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            ContinuationType::Ordinary => "ordinary",
            ContinuationType::Envelope(_) => "envelope",
            ContinuationType::PushInt(..) => "pushint",
            ContinuationType::Quit(_) => "quit",
            ContinuationType::ExcQuit => "exception-quit",
            ContinuationType::Repeat { .. } => "repeat",
            ContinuationType::Again { .. } => "again",
            ContinuationType::Until { .. } => "until",
            ContinuationType::While { check_cond: true, .. } => "while-condition",
            ContinuationType::While { check_cond: false, .. } => "while-body",
        }
    }
}

impl PartialEq for ContinuationType {
    fn eq(&self, other: &Self) -> bool {
        graph_eq(
            &ContinuationData::with_type(self.clone()),
            &ContinuationData::with_type(other.clone()),
        )
    }
}

impl Eq for ContinuationType {}

// Shallow on purpose: nested continuation graphs can be arbitrarily deep.
impl fmt::Debug for ContinuationType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ContinuationType::PushInt(value, _) => write!(f, "PushInt({value})"),
            ContinuationType::Quit(code) => write!(f, "Quit({code})"),
            ContinuationType::Repeat { count, .. } => write!(f, "Repeat({count})"),
            other => write!(f, "{}", other.name()),
        }
    }
}

#[derive(Clone)]
pub struct ContinuationData {
    code: SliceData,
    pub nargs: isize,
    pub savelist: SaveList,
    pub stack: Stack,
    pub type_of: ContinuationType,
}

impl ContinuationData {
    pub const fn new_empty() -> Self {
        Self {
            code: SliceData::new_empty(),
            nargs: -1,
            savelist: SaveList::new(),
            stack: Stack::new(),
            type_of: ContinuationType::Ordinary,
        }
    }

    pub fn copy_without_stack(&self) -> Self {
        Self {
            code: self.code.clone(),
            nargs: self.nargs,
            savelist: self.savelist.clone(),
            stack: Stack::new(),
            type_of: self.type_of.clone(),
        }
    }

    pub fn code(&self) -> &SliceData {
        &self.code
    }

    pub fn code_mut(&mut self) -> &mut SliceData {
        &mut self.code
    }

    /// True for the kinds that carry control data (`nargs`, captured stack, savelist).
    pub fn has_cdata(&self) -> bool {
        matches!(self.type_of, ContinuationType::Ordinary | ContinuationType::Envelope(_))
    }

    /// True when the continuation has control data with a saved c0.
    pub fn has_c0(&self) -> bool {
        self.has_cdata() && self.savelist.get(0).is_some()
    }

    /// True when a jump to this continuation must adjust the stack first: it has control data
    /// with a captured stack or a fixed argument count.
    pub fn needs_stack_adjust(&self) -> bool {
        self.has_cdata() && (!self.stack.is_empty() || self.nargs >= 0)
    }

    /// Gives access to the control data, wrapping a continuation without control data into an
    /// envelope first. Called only where the reference implementation forces control data.
    pub fn force_cdata(&mut self) -> &mut Self {
        if !self.has_cdata() {
            let inner = mem::take(self);
            self.type_of = ContinuationType::Envelope(Arc::new(inner));
        }
        self
    }

    /// Stores `value` into savelist slot `index` if the slot is empty (the reference `define`).
    /// Returns false for a value of the wrong type or an occupied slot; c7 is always accepted.
    /// The caller must have forced control data.
    pub fn define(&mut self, index: usize, value: StackItem) -> bool {
        debug_assert!(self.has_cdata());
        if !SaveList::REGS.contains(&index) || !SaveList::can_put(index, &value) {
            return false;
        }
        if self.savelist.get(index).is_some() {
            return index == 7;
        }
        self.savelist.put_opt(index, value);
        true
    }

    /// Stores `value` into an empty savelist slot; an occupied slot is kept (`define_cN`).
    pub fn define_opt(&mut self, index: usize, value: Option<StackItem>) {
        debug_assert!(self.has_cdata());
        if let Some(value) = value {
            if self.savelist.get(index).is_none() && SaveList::can_put(index, &value) {
                self.savelist.put_opt(index, value);
            }
        }
    }

    pub fn can_put_to_savelist_once(&self, i: usize) -> bool {
        self.savelist.get(i).is_none()
    }

    pub fn move_to_end(&mut self) {
        self.code = SliceData::default()
    }

    pub fn put_to_savelist(&mut self, i: usize, val: StackItem) -> Result<Option<StackItem>> {
        self.savelist.put(i, val)
    }

    pub fn remove_from_savelist(&mut self, i: usize) -> Option<StackItem> {
        self.savelist.remove(i)
    }

    pub fn with_code_and_stack(code: SliceData, stack: Stack) -> Self {
        ContinuationData {
            code,
            nargs: -1,
            savelist: SaveList::new(),
            stack,
            type_of: ContinuationType::Ordinary,
        }
    }

    pub fn with_code(code: SliceData) -> Self {
        Self::with_code_and_stack(code, Stack::new())
    }

    pub fn with_type(type_of: ContinuationType) -> Self {
        ContinuationData {
            code: SliceData::default(),
            nargs: -1,
            savelist: SaveList::new(),
            stack: Stack::new(),
            type_of,
        }
    }

    pub fn withdraw(&mut self) -> Self {
        mem::take(self)
    }

    pub fn drain_reference(&mut self) -> Result<Cell> {
        self.code
            .checked_drain_reference()
            .map_err(|err| error!(ExceptionCode::InvalidOpcode, "drain_reference failed: {}", err))
    }

    /// Moves every owned stack item (savelist, captured stack, child continuations) out.
    pub(crate) fn take_owned_items(&mut self, out: &mut Vec<StackItem>) {
        for creg in SaveList::REGS {
            if let Some(item) = self.savelist.get_mut(creg) {
                out.push(mem::take(item))
            }
        }
        for item in &mut self.stack.storage {
            out.push(mem::take(item))
        }
        self.type_of.take_children(out);
    }
}

impl Default for ContinuationData {
    fn default() -> Self {
        Self::new_empty()
    }
}

// Nested continuations (loop bodies, envelopes, savelists, captured stacks) are released
// with an explicit work list instead of recursive drops.
impl Drop for ContinuationData {
    fn drop(&mut self) {
        if matches!(
            self.type_of,
            ContinuationType::Ordinary | ContinuationType::Quit(_) | ContinuationType::ExcQuit
        ) && self.savelist.is_empty()
            && self.stack.is_empty()
        {
            return;
        }
        // Each moved-out item releases its own nested items iteratively (see `StackItem::drop`).
        let mut items = Vec::new();
        self.take_owned_items(&mut items);
        drop(items);
    }
}

enum EqTask<'a> {
    Item(&'a StackItem, &'a StackItem),
    Cont(&'a ContinuationData, &'a ContinuationData),
}

/// Structural equality of two continuation graphs, without recursion. Pairs of shared nodes
/// already compared are skipped, so shared sub-graphs are not re-expanded.
fn graph_eq(a: &ContinuationData, b: &ContinuationData) -> bool {
    let mut tasks = vec![EqTask::Cont(a, b)];
    let mut seen: HashSet<(usize, usize)> = HashSet::new();
    while let Some(task) = tasks.pop() {
        match task {
            EqTask::Item(x, y) => match (x, y) {
                (StackItem::Continuation(x), StackItem::Continuation(y)) => {
                    if Arc::ptr_eq(x, y) {
                        continue;
                    }
                    let key = (Arc::as_ptr(x) as usize, Arc::as_ptr(y) as usize);
                    if seen.insert(key) {
                        tasks.push(EqTask::Cont(x, y));
                    }
                }
                (StackItem::Tuple(x), StackItem::Tuple(y)) => {
                    if Arc::ptr_eq(x, y) {
                        continue;
                    }
                    if x.len() != y.len() {
                        return false;
                    }
                    for (x, y) in x.iter().zip(y.iter()) {
                        tasks.push(EqTask::Item(x, y));
                    }
                }
                (StackItem::Continuation(_), _)
                | (_, StackItem::Continuation(_))
                | (StackItem::Tuple(_), _)
                | (_, StackItem::Tuple(_)) => return false,
                (x, y) => {
                    if !Stack::eq_item(x, y) {
                        return false;
                    }
                }
            },
            EqTask::Cont(x, y) => {
                if x.code != y.code
                    || x.nargs != y.nargs
                    || x.stack.depth() != y.stack.depth()
                    || !x.type_of.same_shape(&y.type_of)
                {
                    return false;
                }
                for creg in SaveList::REGS {
                    match (x.savelist.get(creg), y.savelist.get(creg)) {
                        (None, None) => (),
                        (Some(x), Some(y)) => tasks.push(EqTask::Item(x, y)),
                        _ => return false,
                    }
                }
                for (x, y) in x.stack.storage.iter().zip(y.stack.storage.iter()) {
                    tasks.push(EqTask::Item(x, y));
                }
                for (x, y) in x.type_of.children().into_iter().zip(y.type_of.children()) {
                    if Arc::ptr_eq(x, y) {
                        continue;
                    }
                    let key = (Arc::as_ptr(x) as usize, Arc::as_ptr(y) as usize);
                    if seen.insert(key) {
                        tasks.push(EqTask::Cont(x, y));
                    }
                }
            }
        }
    }
    true
}

impl PartialEq for ContinuationData {
    fn eq(&self, other: &Self) -> bool {
        graph_eq(self, other)
    }
}

// Shallow on purpose: nested continuation graphs can be arbitrarily deep.
impl fmt::Debug for ContinuationData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let saved = SaveList::REGS
            .iter()
            .filter(|i| self.savelist.get(**i).is_some())
            .map(|i| format!("c{i}"))
            .collect::<Vec<_>>()
            .join(",");
        write!(
            f,
            "ContinuationData {{ type: {:?}, code: {}, nargs: {}, stack depth: {}, saved: [{}] }}",
            self.type_of,
            self.code,
            self.nargs,
            self.stack.depth(),
            saved
        )
    }
}

impl fmt::Display for ContinuationData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{{\n    type: {}\n    code: {}    nargs: {}\n    stack: ",
            self.type_of, self.code, self.nargs
        )?;
        if self.stack.depth() == 0 {
            writeln!(f, "empty")?;
        } else {
            writeln!(f)?;
            for x in self.stack.storage.iter() {
                write!(f, "        {}", x)?;
                writeln!(f)?;
            }
        }
        write!(f, "    savelist: ")?;
        if self.savelist.is_empty() {
            writeln!(f, "empty")?;
        } else {
            writeln!(f)?;
            for i in SaveList::REGS {
                if let Some(item) = self.savelist.get(i) {
                    writeln!(f, "        {}: {}", i, item)?
                }
            }
        }
        write!(f, "}}")
    }
}

impl fmt::Display for ContinuationType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

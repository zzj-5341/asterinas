// SPDX-License-Identifier: MPL-2.0

//! Validation for literal AppArmor attachment DFAs.
//!
//! The table layout follows AppArmor 5.0.2's
//! [`flex_table_serialize`](https://gitlab.com/apparmor/apparmor/-/blob/v5.0.2/parser/libapparmor_re/chfa.cc)
//! format.

use aster_core::{Errno, Error, Result};

const MAGIC: u32 = 0x1b5e_783d;
const HEADER_SIZE: usize = 24;

#[derive(Clone, Copy)]
struct Table<'a> {
    width: usize,
    count: usize,
    data: &'a [u8],
}

impl Table<'_> {
    fn value(&self, index: usize) -> Option<u32> {
        let start = index.checked_mul(self.width)?;
        let bytes = self.data.get(start..start.checked_add(self.width)?)?;
        match self.width {
            2 => Some(u32::from(u16::from_be_bytes(bytes.try_into().ok()?))),
            4 => Some(u32::from_be_bytes(bytes.try_into().ok()?)),
            _ => None,
        }
    }
}

pub(super) fn validate_literal(bytes: &[u8], attachment: &[u8]) -> Result<()> {
    let padding = bytes
        .iter()
        .take(8)
        .position(|byte| *byte != 0)
        .ok_or_else(protocol_error)?;
    let bytes = &bytes[padding..];
    if be_u32(bytes, 0)? != MAGIC
        || usize::try_from(be_u32(bytes, 4)?).ok() != Some(HEADER_SIZE)
        || usize::try_from(be_u32(bytes, 8)?).ok() != Some(bytes.len())
        || be_u16(bytes, 12)? != 0
        || bytes.get(14..22) != Some(b"notflex\0")
        || bytes.get(22..HEADER_SIZE) != Some(&[0, 0])
    {
        return Err(protocol_error());
    }

    let mut position = HEADER_SIZE;
    let accept = table(bytes, &mut position, 1, 4)?;
    let accept2 = table(bytes, &mut position, 7, 4)?;
    let base = table(bytes, &mut position, 2, 4)?;
    let default = state_table(bytes, &mut position, 4)?;
    let next = state_table(bytes, &mut position, 8)?;
    let check = state_table(bytes, &mut position, 3)?;
    if position != bytes.len()
        || base.count < 2
        || accept.count != base.count
        || accept2.count != base.count
        || default.count != base.count
        || next.count != check.count
    {
        return Err(protocol_error());
    }

    for state in 0..base.count {
        let base = usize::try_from(base.value(state).ok_or_else(protocol_error)?)
            .map_err(|_| protocol_error())?;
        if base.checked_add(255).is_none_or(|end| end >= next.count)
            || usize::try_from(default.value(state).ok_or_else(protocol_error)?)
                .ok()
                .is_none_or(|state| state >= accept.count)
        {
            return Err(protocol_error());
        }
    }
    for transition in 0..next.count {
        if usize::try_from(next.value(transition).ok_or_else(protocol_error)?)
            .ok()
            .is_none_or(|state| state >= accept.count)
            || usize::try_from(check.value(transition).ok_or_else(protocol_error)?)
                .ok()
                .is_none_or(|state| state >= accept.count)
        {
            return Err(protocol_error());
        }
    }

    validate_language(attachment, accept, base, default, next, check)
}

fn validate_language(
    attachment: &[u8],
    accept: Table<'_>,
    base: Table<'_>,
    default: Table<'_>,
    next: Table<'_>,
    check: Table<'_>,
) -> Result<()> {
    let mut state = 1;
    if accept.value(state).ok_or_else(protocol_error)? != 0 {
        return Err(protocol_error());
    }

    for (index, expected) in attachment.iter().copied().enumerate() {
        for byte in u8::MIN..=u8::MAX {
            let target = next_state(state, byte, base, default, next, check)?;
            if (byte == expected) != (target != 0) {
                return Err(protocol_error());
            }
        }
        state = next_state(state, expected, base, default, next, check)?;
        if index + 1 < attachment.len() && accept.value(state).ok_or_else(protocol_error)? != 0 {
            return Err(protocol_error());
        }
    }

    if accept.value(state).ok_or_else(protocol_error)? == 0 {
        return Err(protocol_error());
    }
    for byte in u8::MIN..=u8::MAX {
        if next_state(state, byte, base, default, next, check)? != 0 {
            return Err(protocol_error());
        }
    }
    Ok(())
}

fn next_state(
    state: usize,
    byte: u8,
    base: Table<'_>,
    default: Table<'_>,
    next: Table<'_>,
    check: Table<'_>,
) -> Result<usize> {
    let position = usize::try_from(base.value(state).ok_or_else(protocol_error)?)
        .map_err(|_| protocol_error())?
        .checked_add(usize::from(byte))
        .ok_or_else(protocol_error)?;
    let target = if usize::try_from(check.value(position).ok_or_else(protocol_error)?)
        .map_err(|_| protocol_error())?
        == state
    {
        next.value(position).ok_or_else(protocol_error)?
    } else {
        default.value(state).ok_or_else(protocol_error)?
    };
    usize::try_from(target).map_err(|_| protocol_error())
}

fn state_table<'a>(bytes: &'a [u8], position: &mut usize, id: u16) -> Result<Table<'a>> {
    let width = usize::from(be_u16(
        bytes,
        position.checked_add(2).ok_or_else(protocol_error)?,
    )?);
    if !matches!(width, 2 | 4) {
        return Err(protocol_error());
    }
    table(bytes, position, id, width)
}

fn table<'a>(bytes: &'a [u8], position: &mut usize, id: u16, width: usize) -> Result<Table<'a>> {
    if be_u16(bytes, *position)? != id
        || usize::from(be_u16(
            bytes,
            position.checked_add(2).ok_or_else(protocol_error)?,
        )?) != width
        || be_u32(bytes, position.checked_add(4).ok_or_else(protocol_error)?)? != 0
    {
        return Err(protocol_error());
    }
    let count = usize::try_from(be_u32(
        bytes,
        position.checked_add(8).ok_or_else(protocol_error)?,
    )?)
    .map_err(|_| protocol_error())?;
    let data_start = position.checked_add(12).ok_or_else(protocol_error)?;
    let data_end = data_start
        .checked_add(count.checked_mul(width).ok_or_else(protocol_error)?)
        .ok_or_else(protocol_error)?;
    let end = data_end
        .checked_add(7)
        .map(|end| end & !7)
        .ok_or_else(protocol_error)?;
    let data = bytes.get(data_start..data_end).ok_or_else(protocol_error)?;
    if count == 0
        || bytes
            .get(data_end..end)
            .is_none_or(|padding| padding.iter().any(|byte| *byte != 0))
    {
        return Err(protocol_error());
    }
    *position = end;
    Ok(Table { width, count, data })
}

fn be_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let bytes = bytes
        .get(offset..offset.checked_add(2).ok_or_else(protocol_error)?)
        .ok_or_else(protocol_error)?;
    Ok(u16::from_be_bytes(
        bytes.try_into().map_err(|_| protocol_error())?,
    ))
}

fn be_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let bytes = bytes
        .get(offset..offset.checked_add(4).ok_or_else(protocol_error)?)
        .ok_or_else(protocol_error)?;
    Ok(u32::from_be_bytes(
        bytes.try_into().map_err(|_| protocol_error())?,
    ))
}

fn protocol_error() -> Error {
    Error::new(Errno::EPROTO)
}

//! Read-only Windows Event Log source (wevtapi: EvtQuery/EvtNext/EvtRender and
//! bookmarks). No subscription, audit-policy or channel configuration is changed.
use super::collector::{EventSource, RawEvent, Resume};
use crate::Result;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS,
};
use windows_sys::Win32::System::EventLog::{
    EvtClose, EvtCreateBookmark, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryForwardDirection,
    EvtRender, EvtRenderBookmark, EvtRenderEventXml, EvtSeek, EvtSeekRelativeToBookmark,
    EvtSeekStrict, EvtUpdateBookmark, EVT_HANDLE,
};

/// Rendered XML larger than this is not copied; the collector records it as oversized.
const MAX_RENDER_BYTES: u32 = 1024 * 1024;

struct Handle(EVT_HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: the handle came from a wevtapi call and is closed once.
            unsafe { EvtClose(self.0) };
        }
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

fn last_error(context: &str) -> crate::Error {
    // SAFETY: reads the calling thread's last-error value.
    let code = unsafe { GetLastError() };
    format!("{context} failed (Windows error {code})").into()
}

/// Render an event or bookmark handle to a UTF-16 XML string.
fn render(handle: EVT_HANDLE, flags: u32) -> Result<Option<String>> {
    let mut used = 0u32;
    let mut count = 0u32;
    // SAFETY: a null buffer of size 0 asks for the required size.
    let ok = unsafe { EvtRender(0, handle, flags, 0, null_mut(), &mut used, &mut count) };
    if ok == 0 {
        // SAFETY: as above.
        let code = unsafe { GetLastError() };
        if code != ERROR_INSUFFICIENT_BUFFER {
            return Err(format!("EvtRender failed (Windows error {code})").into());
        }
    }
    if used > MAX_RENDER_BYTES {
        return Ok(None);
    }
    let mut buf = vec![0u16; (used as usize).div_ceil(2)];
    // SAFETY: `buf` holds at least `used` bytes.
    let ok = unsafe {
        EvtRender(
            0,
            handle,
            flags,
            used,
            buf.as_mut_ptr().cast(),
            &mut used,
            &mut count,
        )
    };
    if ok == 0 {
        return Err(last_error("EvtRender"));
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Ok(Some(String::from_utf16_lossy(&buf[..len])))
}

pub struct WinEventSource {
    channel: String,
    query: Option<Handle>,
    bookmark: Option<Handle>,
}

impl WinEventSource {
    pub fn new(channel: &str) -> Self {
        Self {
            channel: channel.to_owned(),
            query: None,
            bookmark: None,
        }
    }

    fn query_all(&self) -> Result<Handle> {
        let path = wide(&self.channel);
        // SAFETY: `path` is NUL-terminated; a null query selects all events.
        let handle = unsafe {
            EvtQuery(
                0,
                path.as_ptr(),
                null(),
                EvtQueryChannelPath | EvtQueryForwardDirection,
            )
        };
        if handle == 0 {
            return Err(last_error(&format!("EvtQuery({})", self.channel)));
        }
        Ok(Handle(handle))
    }
}

impl EventSource for WinEventSource {
    fn channel(&self) -> &str {
        &self.channel
    }

    fn open(&mut self, cursor: Option<&str>) -> Result<Resume> {
        let query = self.query_all()?;
        let Some(xml) = cursor else {
            // SAFETY: null creates an empty bookmark.
            let bookmark = unsafe { EvtCreateBookmark(null()) };
            if bookmark == 0 {
                return Err(last_error("EvtCreateBookmark"));
            }
            self.bookmark = Some(Handle(bookmark));
            self.query = Some(query);
            return Ok(Resume::FromOldest);
        };
        let text = wide(xml);
        // SAFETY: `text` is NUL-terminated bookmark XML from our checkpoint.
        let bookmark = unsafe { EvtCreateBookmark(text.as_ptr()) };
        if bookmark == 0 {
            // A corrupt bookmark is a lost cursor, never a jump to future events.
            // SAFETY: as above.
            let fresh = unsafe { EvtCreateBookmark(null()) };
            if fresh == 0 {
                return Err(last_error("EvtCreateBookmark"));
            }
            self.bookmark = Some(Handle(fresh));
            self.query = Some(query);
            return Ok(Resume::CursorLost);
        }
        let bookmark = Handle(bookmark);
        // SAFETY: both handles are valid; strict seek fails if the bookmarked
        // record no longer exists instead of silently moving elsewhere.
        let sought = unsafe {
            EvtSeek(
                query.0,
                1,
                bookmark.0,
                0,
                EvtSeekRelativeToBookmark | EvtSeekStrict,
            )
        };
        self.bookmark = Some(bookmark);
        if sought != 0 {
            self.query = Some(query);
            Ok(Resume::AfterCursor)
        } else {
            // Restart from the oldest retained event; the collector reports the gap.
            drop(query);
            self.query = Some(self.query_all()?);
            Ok(Resume::CursorLost)
        }
    }

    fn next_batch(&mut self, max: usize) -> Result<Vec<RawEvent>> {
        let query = self.query.as_ref().ok_or("event query is not open")?;
        let bookmark = self.bookmark.as_ref().ok_or("bookmark is not open")?;
        let mut handles = vec![0isize; max.max(1)];
        let mut returned = 0u32;
        // SAFETY: `handles` has room for `max` handles.
        let ok = unsafe {
            EvtNext(
                query.0,
                handles.len() as u32,
                handles.as_mut_ptr(),
                1000,
                0,
                &mut returned,
            )
        };
        if ok == 0 {
            // SAFETY: reads the last-error value of this thread.
            let code = unsafe { GetLastError() };
            if code == ERROR_NO_MORE_ITEMS {
                return Ok(Vec::new());
            }
            return Err(format!("EvtNext failed (Windows error {code})").into());
        }
        let owned: Vec<Handle> = handles[..returned as usize]
            .iter()
            .map(|h| Handle(*h))
            .collect();
        let mut events = Vec::with_capacity(owned.len());
        for event in &owned {
            let xml = render(event.0, EvtRenderEventXml)?
                // Too large to copy: hand the collector an oversized marker.
                .unwrap_or_else(|| "x".repeat(super::MAX_EVENT_XML_BYTES + 1));
            events.push(RawEvent { xml });
            // SAFETY: both handles are valid.
            if unsafe { EvtUpdateBookmark(bookmark.0, event.0) } == 0 {
                return Err(last_error("EvtUpdateBookmark"));
            }
        }
        Ok(events)
    }

    fn cursor(&mut self) -> Result<String> {
        let bookmark = self.bookmark.as_ref().ok_or("bookmark is not open")?;
        render(bookmark.0, EvtRenderBookmark)?.ok_or_else(|| "bookmark too large".into())
    }
}

#[cfg(test)]
mod tests {
    use super::super::collector::{collect, tests::temp_paths};
    use super::*;

    /// Reads a few events from a standard channel present on every Windows
    /// installation; read-only. The second run must resume after the cursor.
    #[test]
    fn reads_and_resumes_a_real_channel() {
        let (dir, paths) = temp_paths("winevt");
        let mut source = WinEventSource::new("Application");
        let first = collect(&mut source, &paths, 5);
        assert!(first.channel_available, "{first:?}");
        assert_eq!(first.status, "ok", "{first:?}");
        if first.received > 0 {
            let mut source = WinEventSource::new("Application");
            let second = collect(&mut source, &paths, 5);
            assert_eq!(second.resumed_from, Some("cursor"), "{second:?}");
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_channel_is_degraded_not_empty() {
        let (dir, paths) = temp_paths("winevt-missing");
        let mut source = WinEventSource::new("AegisGuard-Nonexistent-Channel/Operational");
        let health = collect(&mut source, &paths, 5);
        assert_eq!(health.status, "degraded");
        assert!(!health.channel_available);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn corrupt_bookmark_is_a_lost_cursor() {
        let mut source = WinEventSource::new("Application");
        assert_eq!(
            source.open(Some("<not-a-bookmark")).unwrap(),
            Resume::CursorLost
        );
    }
}

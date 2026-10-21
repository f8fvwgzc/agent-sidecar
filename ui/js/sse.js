// A Server-Sent Events text parser (the event-stream format of the HTML standard), used to replay
// ui/fixtures/events.sse. The live console uses the browser's EventSource instead.

/**
 * Parses an event-stream text into [{id, event, data}] (data is the raw string; multi-line
 * data joined with "\n"). Comment lines (": keepalive") are counted, not returned.
 */
export function parseSse(text) {
  const events = [];
  let comments = 0;
  let id = null;
  let event = '';
  let data = [];
  let hasData = false;
  const dispatch = () => {
    if (hasData) events.push({ id, event: event || 'message', data: data.join('\n') });
    event = '';
    data = [];
    hasData = false;
  };
  const lines = String(text).replace(/\r\n?/g, '\n').split('\n');
  for (const line of lines) {
    if (line === '') {
      dispatch();
      continue;
    }
    if (line.startsWith(':')) {
      comments++;
      continue;
    }
    const i = line.indexOf(':');
    const field = i < 0 ? line : line.slice(0, i);
    let value = i < 0 ? '' : line.slice(i + 1);
    if (value.startsWith(' ')) value = value.slice(1);
    if (field === 'data') {
      data.push(value);
      hasData = true;
    } else if (field === 'event') {
      event = value;
    } else if (field === 'id') {
      if (!value.includes('\0')) id = value;
    }
  }
  dispatch();
  return { events, comments };
}

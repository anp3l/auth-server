import { UAParser } from 'ua-parser-js';

export interface ParsedUserAgent {
  browser: string;
  os: string;
  device: string;
}

/**
 * Parse User-Agent header to extract browser, OS, device information.
 */
export function parseUserAgent(userAgent: string): ParsedUserAgent {
  const parser = new UAParser(userAgent);
  const result = parser.getResult();

  return {
    browser: result.browser.name 
      ? `${result.browser.name} ${result.browser.version || ''}`.trim()
      : 'Unknown',
    os: result.os.name 
      ? `${result.os.name} ${result.os.version || ''}`.trim()
      : 'Unknown',
    device: result.device.type || 'Desktop'
  };
}

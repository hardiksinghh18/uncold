import { google } from "googleapis";
import crypto from "crypto";
import { sanitizeHeaderValue } from "./security";

interface SendEmailParams {
  accessToken: string;
  refreshToken?: string | null;
  to: string;
  subject: string;
  body: string;
  fromEmail?: string;
  senderName?: string;
  trackingPixelUrl?: string;
}

/**
 * Creates a clean RFC 2822 MIME email message with multipart/alternative
 * supporting both plain text and HTML with an invisible open tracking pixel.
 */
function createRawEmail({
  to,
  subject,
  body,
  fromEmail,
  senderName,
  trackingPixelUrl,
}: {
  to: string;
  subject: string;
  body: string;
  fromEmail?: string;
  senderName?: string;
  trackingPixelUrl?: string;
}): string {
  const safeTo = sanitizeHeaderValue(to).replace(/[<>]/g, "");
  const safeFromEmail = fromEmail ? sanitizeHeaderValue(fromEmail).replace(/[<>]/g, "") : "";
  const safeSenderName = senderName ? sanitizeHeaderValue(senderName).replace(/"/g, "'") : "";

  const fromHeader = safeFromEmail
    ? safeSenderName
      ? `From: "${safeSenderName}" <${safeFromEmail}>\r\n`
      : `From: <${safeFromEmail}>\r\n`
    : "";

  // Normalize markdown bullets (* / -) to clean Unicode bullets (•) for plain text
  const plainTextBody = body
    .replace(/^[ \t]*[\*\-][ \t]+/gm, "• ")
    .replace(/\*\*(.*?)\*\*/g, "$1");

  // Format clean HTML paragraphs and styled bullet lists
  const formatHtmlBody = (rawText: string): string => {
    const escaped = rawText
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>");

    const lines = escaped.split(/\r?\n/);
    const out: string[] = [];
    let inList = false;

    for (const line of lines) {
      const bulletMatch = line.match(/^[ \t]*(?:•|\*|-)[ \t]+(.*)$/);
      if (bulletMatch) {
        if (!inList) {
          out.push('<ul style="margin: 8px 0 12px 0; padding-left: 20px;">');
          inList = true;
        }
        out.push(`<li style="margin-bottom: 6px;">${bulletMatch[1]}</li>`);
      } else {
        if (inList) {
          out.push("</ul>");
          inList = false;
        }
        if (line.trim() === "") {
          out.push("<br/>");
        } else {
          out.push(`${line}<br/>`);
        }
      }
    }
    if (inList) out.push("</ul>");
    return out.join("\n").replace(/(<\/ul>)\s*<br\/>/g, "$1");
  };

  // Prepare HTML version with formatted paragraphs and tracking pixel
  const htmlBody = `
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
  </head>
  <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; font-size: 14px; line-height: 1.6; color: #222;">
    ${formatHtmlBody(body)}
    ${
      trackingPixelUrl
        ? `<img src="${trackingPixelUrl}" width="1" height="1" alt="" style="display:none;width:1px;height:1px;border:0;" />`
        : ""
    }
  </body>
</html>
`.trim();

  const boundary = `====boundary_${crypto.randomBytes(12).toString("hex")}====`;

  // Clean up non-ASCII unicode dash/quotes (e.g. en-dash –, em-dash —, smart quotes) to avoid mojibake (â€“)
  const cleanSubject = subject
    .replace(/[\u2010\u2011\u2012\u2013\u2014\u2015]/g, "-")
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/[\u201C\u201D]/g, '"')
    .trim();

  // RFC 2047 encode the subject if it contains any special or non-ASCII characters
  const encodedSubject = /[^\x20-\x7E]/.test(cleanSubject)
    ? `=?UTF-8?B?${Buffer.from(cleanSubject, "utf-8").toString("base64")}?=`
    : cleanSubject;

  const emailLines = [
    fromHeader,
    `To: <${safeTo}>\r\n`,
    `Subject: ${encodedSubject}\r\n`,
    "MIME-Version: 1.0\r\n",
    `Content-Type: multipart/alternative; boundary="${boundary}"\r\n\r\n`,
    `--${boundary}\r\n`,
    "Content-Type: text/plain; charset=UTF-8\r\n",
    "Content-Transfer-Encoding: 8bit\r\n\r\n",
    plainTextBody,
    "\r\n\r\n",
    `--${boundary}\r\n`,
    "Content-Type: text/html; charset=UTF-8\r\n",
    "Content-Transfer-Encoding: 8bit\r\n\r\n",
    htmlBody,
    "\r\n\r\n",
    `--${boundary}--\r\n`,
  ].filter(Boolean);

  const rawMessage = emailLines.join("");
  return Buffer.from(rawMessage)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * Sends an email directly from the authenticated user's Gmail mailbox using OAuth 2.0.
 */
export async function sendGmailMessage({
  accessToken,
  refreshToken,
  to,
  subject,
  body,
  fromEmail,
  senderName,
  trackingPixelUrl,
}: SendEmailParams): Promise<{ messageId: string; threadId: string }> {
  const oauth2Client = new google.auth.OAuth2(
    process.env.GOOGLE_CONSOLE_CLIENT_ID,
    process.env.GOOGLE_CONSOLE_CLIENT_SECRET
  );

  oauth2Client.setCredentials({
    access_token: accessToken,
    refresh_token: refreshToken || undefined,
  });

  const gmail = google.gmail({ version: "v1", auth: oauth2Client });
  const raw = createRawEmail({ to, subject, body, fromEmail, senderName, trackingPixelUrl });

  const res = await gmail.users.messages.send({
    userId: "me",
    requestBody: {
      raw,
    },
  });

  return {
    messageId: res.data.id || "",
    threadId: res.data.threadId || "",
  };
}

/**
 * Checks a Gmail thread for incoming replies from the recipient.
 */
export async function checkThreadReplies({
  accessToken,
  refreshToken,
  threadId,
  userEmail,
}: {
  accessToken: string;
  refreshToken?: string | null;
  threadId: string;
  userEmail: string;
}): Promise<{ hasReply: boolean; snippet?: string; replyDate?: string }> {
  const oauth2Client = new google.auth.OAuth2(
    process.env.GOOGLE_CONSOLE_CLIENT_ID,
    process.env.GOOGLE_CONSOLE_CLIENT_SECRET
  );

  oauth2Client.setCredentials({
    access_token: accessToken,
    refresh_token: refreshToken || undefined,
  });

  const gmail = google.gmail({ version: "v1", auth: oauth2Client });

  try {
    const threadRes = await gmail.users.threads.get({
      userId: "me",
      id: threadId,
      format: "metadata",
      metadataHeaders: ["From", "Date"],
    });

    const messages = threadRes.data.messages || [];
    if (messages.length > 1) {
      // Find messages sent from someone other than user
      const incomingMessage = messages.slice(1).find((msg) => {
        const fromHeader = msg.payload?.headers?.find(
          (h) => h.name?.toLowerCase() === "from"
        )?.value;
        return fromHeader && !fromHeader.toLowerCase().includes(userEmail.toLowerCase());
      });

      if (incomingMessage) {
        return {
          hasReply: true,
          snippet: incomingMessage.snippet || "New reply received",
          replyDate: incomingMessage.internalDate
            ? new Date(parseInt(incomingMessage.internalDate, 10)).toISOString()
            : new Date().toISOString(),
        };
      }
    }
  } catch (err: any) {
    console.warn(`Thread check notice for [${threadId}]:`, err.message);
  }

  return { hasReply: false };
}

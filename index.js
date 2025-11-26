require("dotenv").config();
const express = require("express");
const request = require("request-promise-native");
const NodeCache = require("node-cache");
const session = require("express-session");
const opn = require("open");
const crypto = require("crypto");
const app = express();

const PORT = process.env.PORT || 3000;

const refreshTokenStore = {};
const accessTokenCache = new NodeCache({ deleteOnExpire: true });

if (
  !process.env.CLIENT_ID ||
  !process.env.CLIENT_SECRET ||
  !process.env.SMS_TOKEN
) {
  throw new Error(
    "Missing CLIENT_ID or CLIENT_SECRE or SMS_TOKEN environment variable."
  );
}

//===========================================================================//
//  HUBSPOT APP CONFIGURATION
//
//  All the following values must match configuration settings in your app.
//  They will be used to build the OAuth URL, which users visit to begin
//  installing. If they don't match your app's configuration, users will
//  see an error page.

// Replace the following with the values from your app auth config,
// or set them as environment variables before running.
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const SMS_TOKEN = process.env.SMS_TOKEN;
// Scopes for this app will default to `crm.objects.contacts.read`
// To request others, set the SCOPE environment variable instead
let SCOPES = ["crm.objects.contacts.read"];
if (process.env.SCOPE) {
  SCOPES = process.env.SCOPE.split(/ |, ?|%20/).join(" ");
}

// On successful install, users will be redirected to /oauth-callback
// Use environment variable for production (Fly.io), fallback to localhost for development
const REDIRECT_URI =
  process.env.REDIRECT_URI || `http://localhost:${PORT}/oauth-callback`;

//===========================================================================//

// Use a session to keep track of client ID
// Use environment variable for session secret (required for production)
// Generate random secret only for local development
const SESSION_SECRET =
  process.env.SESSION_SECRET || Math.random().toString(36).substring(2);
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);

// Capture raw body for HubSpot signature validation
app.use(
  express.json({
    verify: (req, res, buf) => {
      req.rawBody = buf.toString("utf8");
    },
  })
);

//================================//
//   HubSpot Webhook Validation   //
//================================//

// Helper: validate X-HubSpot-Signature-v3
function isValidHubspotRequest(req) {
  console.log("🔍 [Auth] Starting HubSpot signature validation");

  // Parse headers needed to validate signature
  const signatureHeader = req.headers["x-hubspot-signature-v3"] || "";
  const timestampHeader = req.headers["x-hubspot-request-timestamp"] || "";

  console.log("🔍 [Auth] Headers received:", {
    signature: signatureHeader
      ? `${signatureHeader.substring(0, 20)}...`
      : "MISSING",
    timestamp: timestampHeader || "MISSING",
  });

  if (!signatureHeader || !timestampHeader) {
    console.warn("❌ [Auth] REJECTED: Missing signature or timestamp");
    console.warn("   - Signature present:", !!signatureHeader);
    console.warn("   - Timestamp present:", !!timestampHeader);
    return false;
  }

  // Validate timestamp
  const MAX_ALLOWED_TIMESTAMP = 300000; // 5 minutes in milliseconds
  const currentTime = Date.now();
  const timestamp = parseInt(timestampHeader, 10);

  console.log("🔍 [Auth] Timestamp validation:", {
    received: timestamp,
    current: currentTime,
    ageDiffMs: currentTime - timestamp,
    maxAgeMs: MAX_ALLOWED_TIMESTAMP,
    isValid: currentTime - timestamp <= MAX_ALLOWED_TIMESTAMP,
  });

  if (currentTime - timestamp > MAX_ALLOWED_TIMESTAMP) {
    console.warn("❌ [Auth] REJECTED: Timestamp is invalid, reject request");
    console.warn(
      `   - Age: ${Math.round((currentTime - timestamp) / 1000)}s (max: ${
        MAX_ALLOWED_TIMESTAMP / 1000
      }s)`
    );
    return false;
  }

  // Concatenate request method, URI, body, and header timestamp
  const uri = `https://${req.hostname}${req.url}`;
  const rawString = `${req.method}${uri}${JSON.stringify(
    req.body
  )}${timestampHeader}`;

  console.log("🔍 [Auth] Building signature base string:", {
    method: req.method,
    uri: uri,
    bodyStringified: JSON.stringify(req.body),
    bodyLength: JSON.stringify(req.body).length,
    timestamp: timestampHeader,
    rawStringLength: rawString.length,
    rawStringPreview:
      rawString.length > 200 ? `${rawString.substring(0, 200)}...` : rawString,
  });

  // Create HMAC SHA-256 hash from resulting string above, then base64-encode it
  const hashedString = crypto
    .createHmac("sha256", CLIENT_SECRET)
    .update(rawString)
    .digest("base64");

  console.log("🔍 [Auth] Signature comparison:", {
    receivedSignature: signatureHeader,
    expectedSignature: hashedString,
    signaturesMatch: signatureHeader === hashedString,
  });

  // Validate signature: compare computed signature vs. signature in header
  // Use timing-safe compare
  const sigBuf = Buffer.from(signatureHeader);
  const hashBuf = Buffer.from(hashedString);

  console.log("🔍 [Auth] Buffer comparison:", {
    receivedLength: sigBuf.length,
    expectedLength: hashBuf.length,
    lengthsMatch: sigBuf.length === hashBuf.length,
  });

  if (sigBuf.length !== hashBuf.length) {
    console.warn("❌ [Auth] REJECTED: Signature buffer lengths don't match");
    return false;
  }

  const isValid = crypto.timingSafeEqual(sigBuf, hashBuf);

  if (isValid) {
    console.log("✅ [Auth] Signature matches! Request is valid.");
  } else {
    console.warn("❌ [Auth] Signature does not match: request is invalid");
  }

  return isValid;
}

//================================//
//   Running the OAuth 2.0 Flow   //
//================================//

// Step 1
// Build the authorization URL to redirect a user
// to when they choose to install the app
const authUrl =
  "https://app.hubspot.com/oauth/authorize" +
  `?client_id=${encodeURIComponent(CLIENT_ID)}` + // app's client ID
  `&scope=${encodeURIComponent(SCOPES)}` + // scopes being requested by the app
  `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}`; // where to send the user after the consent page

// Redirect the user from the installation page to
// the authorization URL
app.get("/install", (req, res) => {
  console.log("");
  console.log("=== Initiating OAuth 2.0 flow with HubSpot ===");
  console.log("");
  console.log("===> Step 1: Redirecting user to your app's OAuth URL");
  res.redirect(authUrl);
  console.log("===> Step 2: User is being prompted for consent by HubSpot");
});

// Step 2
// The user is prompted to give the app access to the requested
// resources. This is all done by HubSpot, so no work is necessary
// on the app's end

// Step 3
// Receive the authorization code from the OAuth 2.0 Server,
// and process it based on the query parameters that are passed
app.get("/oauth-callback", async (req, res) => {
  console.log("===> Step 3: Handling the request sent by the server");

  // Received a user authorization code, so now combine that with the other
  // required values and exchange both for an access token and a refresh token
  if (req.query.code) {
    console.log("       > Received an authorization token");

    const authCodeProof = {
      grant_type: "authorization_code",
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uri: REDIRECT_URI,
      code: req.query.code,
    };

    // Step 4
    // Exchange the authorization code for an access token and refresh token
    console.log(
      "===> Step 4: Exchanging authorization code for an access token and refresh token"
    );
    const token = await exchangeForTokens(req.sessionID, authCodeProof);
    if (token.message) {
      return res.redirect(`/error?msg=${token.message}`);
    }

    // Once the tokens have been retrieved, use them to make a query
    // to the HubSpot API
    res.redirect(`/`);
  }
});

//==========================================//
//   Exchanging Proof for an Access Token   //
//==========================================//

const exchangeForTokens = async (userId, exchangeProof) => {
  try {
    const responseBody = await request.post(
      "https://api.hubapi.com/oauth/v1/token",
      {
        form: exchangeProof,
      }
    );
    // Usually, this token data should be persisted in a database and associated with
    // a user identity.
    const tokens = JSON.parse(responseBody);
    refreshTokenStore[userId] = tokens.refresh_token;
    accessTokenCache.set(
      userId,
      tokens.access_token,
      Math.round(tokens.expires_in * 0.75)
    );

    console.log("       > Received an access token and refresh token");
    return tokens.access_token;
  } catch (e) {
    console.error(
      `       > Error exchanging ${exchangeProof.grant_type} for access token`
    );
    console.error(e.response.body);
    return JSON.parse(e.response.body);
  }
};

const refreshAccessToken = async (userId) => {
  const refreshTokenProof = {
    grant_type: "refresh_token",
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    redirect_uri: REDIRECT_URI,
    refresh_token: refreshTokenStore[userId],
  };
  return await exchangeForTokens(userId, refreshTokenProof);
};

const getAccessToken = async (userId) => {
  // If the access token has expired, retrieve
  // a new one using the refresh token
  if (!accessTokenCache.get(userId)) {
    console.log("Refreshing expired access token");
    await refreshAccessToken(userId);
  }
  return accessTokenCache.get(userId);
};

const isAuthorized = (userId) => {
  return refreshTokenStore[userId] ? true : false;
};

//====================================================//
//   Using an Access Token to Query the HubSpot API   //
//====================================================//

const getContact = async (accessToken) => {
  console.log("");
  console.log(
    "=== Retrieving a contact from HubSpot using the access token ==="
  );
  try {
    const headers = {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    };
    console.log(
      "===> Replace the following request.get() to test other API calls"
    );
    console.log(
      "===> request.get('https://api.hubapi.com/contacts/v1/lists/all/contacts/all?count=1')"
    );
    const result = await request.get(
      "https://api.hubapi.com/contacts/v1/lists/all/contacts/all?count=1",
      {
        headers: headers,
      }
    );

    return JSON.parse(result).contacts[0];
  } catch (e) {
    console.error("  > Unable to retrieve contact");
    return JSON.parse(e.response.body);
  }
};

//========================================//
//   Displaying information to the user   //
//========================================//

const displayContactName = (res, contact) => {
  if (contact.status === "error") {
    res.write(
      `<p>Unable to retrieve contact! Error Message: ${contact.message}</p>`
    );
    return;
  }
  const { firstname, lastname } = contact.properties;
  res.write(`<p>Contact name: ${firstname.value} ${lastname.value}</p>`);
};

app.get("/", async (req, res) => {
  res.setHeader("Content-Type", "text/html");
  res.write(`<h2>HubSpot OAuth 2.0 Quickstart App</h2>`);
  if (isAuthorized(req.sessionID)) {
    const accessToken = await getAccessToken(req.sessionID);
    const contact = await getContact(accessToken);
    res.write(`<h4>Access token: ${accessToken}</h4>`);
    displayContactName(res, contact);
  } else {
    res.write(`<a href="/install"><h3>Install the app</h3></a>`);
  }
  res.end();
});

app.get("/error", (req, res) => {
  res.setHeader("Content-Type", "text/html");
  res.write(`<h4>Error: ${req.query.msg}</h4>`);
  res.end();
});

//========================================//
//   HubSpot Workflow Action Callback    //
//========================================//

// SMS Gateway Configuration
const SMS_FROM_NUMBER = "02825610051"; // New Zealand phone number
const SMS_GATEWAY_URL = "https://portal.kiwivoip.co.nz/api/v1/sms/messages";

// Helper function to normalize phone number to accepted format (02XXX or +642XXX)
function normalizePhoneNumber(phone) {
  if (!phone) return null;

  // Trim whitespace
  phone = phone.trim();

  // If already in +642XXX format, return as is
  if (phone.startsWith("+64")) {
    return phone;
  }

  // Remove all non-digit characters for processing
  let cleaned = phone.replace(/\D/g, "");

  // If it starts with 64 (without +), convert to +642XXX format
  if (cleaned.startsWith("64")) {
    return "+" + cleaned;
  }

  // If it starts with 0, keep as 02XXX format
  if (cleaned.startsWith("0")) {
    return cleaned;
  }

  // If it doesn't have a prefix, assume it's a local NZ number starting with 2
  // Add 0 prefix to make it 02XXX format
  return "0" + cleaned;
}

// Route: HubSpot workflow action callback
app.post("/hubspot/workflow/send-sms", async (req, res) => {
  console.log("📨 [SMS] Received HubSpot workflow request");

  if (!isValidHubspotRequest(req)) {
    console.warn("❌ [SMS] Invalid HubSpot signature, rejecting request");
    return res.status(401).send("Invalid HubSpot signature");
  }

  // At this point, request is trusted as coming from HubSpot
  console.log("✅ [SMS] Valid HubSpot workflow request received");
  console.log("Body:", JSON.stringify(req.body, null, 2));

  try {
    // Extract phone and message from the request body
    const phone = req.body?.fields?.phone || req.body?.inputFields?.phone;
    const message = req.body?.fields?.message || req.body?.inputFields?.message;

    if (!phone || !message) {
      console.error("❌ [SMS] Missing required fields:", {
        phone: !!phone,
        message: !!message,
      });
      return res.status(400).json({
        error: "Missing required fields",
        required: ["phone", "message"],
      });
    }

    // Normalize phone number
    const normalizedPhone = normalizePhoneNumber(phone);
    if (!normalizedPhone) {
      console.error("❌ [SMS] Invalid phone number format:", phone);
      return res.status(400).json({
        error: "Invalid phone number format",
        provided: phone,
      });
    }

    console.log("📤 [SMS] Sending SMS:", {
      from: SMS_FROM_NUMBER,
      to: normalizedPhone,
      messageLength: message.length,
    });

    // Send SMS via KiwiVoIP API
    const smsPayload = {
      from: SMS_FROM_NUMBER,
      to: normalizedPhone,
      text: message,
    };

    // Proxy configuration for SMS requests
    const PROXY_URL =
      "http://1e60202a8f04c085ef13__cr.nz:63caa473cb031a9e@gw.dataimpulse.com:10000";

    const smsResponse = await request.post(SMS_GATEWAY_URL, {
      proxy: PROXY_URL,
      tunnel: true, // Explicitly enable tunneling for HTTPS through HTTP proxy
      headers: {
        authorization: `Bearer ${SMS_TOKEN}`,
        "content-type": "application/json",
      },
      json: smsPayload,
      timeout: 30000, // 30 second timeout
    });

    console.log("✅ [SMS] SMS sent successfully:", smsResponse);
    return res.status(200).json({
      success: true,
      message: "SMS sent successfully",
      response: smsResponse,
    });
  } catch (error) {
    console.error("❌ [SMS] Error sending SMS:", error.message);
    if (error.response) {
      console.error("   Response body:", error.response.body);
      return res.status(error.response.statusCode || 500).json({
        error: "Failed to send SMS",
        details: error.response.body,
      });
    }
    return res.status(500).json({
      error: "Internal server error",
      message: error.message,
    });
  }
});

app.listen(PORT, () =>
  console.log(`=== Starting your app on port ${PORT} ===`)
);

// Only open browser in local development
if (process.env.NODE_ENV !== "production" && !process.env.FLY_APP_NAME) {
  opn(`http://localhost:${PORT}`);
}

/**
 * src/github-images.js
 * Uploads job images to the GitHub Pages static repo so the DB stores a URL
 * instead of a raw base64 blob.  Requires GITHUB_TOKEN (fine-grained PAT with
 * "Contents: read & write" on cherry19899/cherry19899.github.io).
 *
 * If GITHUB_TOKEN is not set the helper falls back to keeping base64 as-is,
 * so the app still works without the token (images just won't be migrated).
 */

const GITHUB_TOKEN  = process.env.GITHUB_TOKEN || '';
const GITHUB_OWNER  = 'cherry19899';
const GITHUB_REPO   = 'cherry19899.github.io';
const PAGES_BASE    = 'https://cherry19899.github.io';
const IMAGES_PREFIX = 'assets/images';

/**
 * Upload a single base64 data-URL to GitHub Pages and return the public URL.
 * Returns the original string unchanged if GITHUB_TOKEN is missing or upload fails.
 */
async function uploadBase64ToGitHub(dataUrl, filename) {
  if (!GITHUB_TOKEN) return dataUrl;

  const match = dataUrl.match(/^data:([^;]+);base64,(.+)$/s);
  if (!match) return dataUrl;

  const content = match[2]; // raw base64, no header
  const apiPath = `${IMAGES_PREFIX}/${filename}`;
  const apiUrl  = `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${apiPath}`;

  // Check if file already exists (need its SHA to update)
  let sha;
  try {
    const check = await fetch(apiUrl, {
      headers: { Authorization: `Bearer ${GITHUB_TOKEN}`, 'User-Agent': 'workpro-api' },
    });
    if (check.ok) {
      const meta = await check.json();
      sha = meta.sha;
    }
  } catch (_) {}

  const body = {
    message: `upload: job image ${filename}`,
    content,
    ...(sha ? { sha } : {}),
  };

  try {
    const r = await fetch(apiUrl, {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${GITHUB_TOKEN}`,
        'Content-Type': 'application/json',
        'User-Agent': 'workpro-api',
      },
      body: JSON.stringify(body),
    });
    if (!r.ok) {
      const err = await r.text();
      console.error(`[github-images] upload failed for ${filename}: ${r.status} ${err.slice(0, 200)}`);
      return dataUrl; // fallback
    }
    return `${PAGES_BASE}/${apiPath}`;
  } catch (e) {
    console.error('[github-images] network error:', e.message);
    return dataUrl;
  }
}

/**
 * Process an images array: upload any base64 items to GitHub and return the
 * array with URLs in place of base64 strings.
 * jobId is used to derive filenames (job{jobId}_{index}.jpg).
 */
async function processJobImages(images, jobId) {
  if (!Array.isArray(images) || images.length === 0) return { images, upload_failed: false };
  const results = [];
  let upload_failed = false;
  for (let i = 0; i < images.length; i++) {
    const img = images[i];
    if (typeof img === 'string' && img.startsWith('data:')) {
      const mime = img.match(/^data:([^;]+)/)?.[1] || 'image/jpeg';
      const ext  = mime.includes('png') ? 'png' : mime.includes('gif') ? 'gif' : 'jpg';
      const filename = `job${jobId}_${i + 1}.${ext}`;
      const uploaded = await uploadBase64ToGitHub(img, filename);
      if (uploaded === img) upload_failed = true; // still base64 — upload failed
      results.push(uploaded);
    } else {
      results.push(img);
    }
  }
  return { images: results, upload_failed };
}

module.exports = { uploadBase64ToGitHub, processJobImages };

// AI Tutor endpoint removed. This function intentionally returns 410 Gone
// to indicate the feature has been retired. Keeping a stub file avoids
// runtime errors if the endpoint is still referenced by older deployments.

export async function onRequest(context) {
  return new Response(JSON.stringify({
    error: 'AI Tutor feature removed',
    message: 'This endpoint has been disabled and is no longer available.'
  }), {
    status: 410,
    headers: { 'content-type': 'application/json' }
  });
}
  


export const RESOURCE_IDS = Object.freeze({
  studentMemos: 'student-memos',
  instructorNotices: 'instructor-notices',
});

export function markResource(response, resourceId) {
  response.setHeader('X-Aleph-Resource-ID', resourceId);
}

export function withResourceId(resourceId, value) {
  return { ...value, resourceId };
}

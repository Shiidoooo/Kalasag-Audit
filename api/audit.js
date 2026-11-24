import { handleAudit, wrapVercelHandler } from '../src/apiHandlers.js';

export default wrapVercelHandler('POST', handleAudit);

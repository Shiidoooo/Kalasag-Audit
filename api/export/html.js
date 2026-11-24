import { handleExportHtml, wrapVercelHandler } from '../../src/apiHandlers.js';

export default wrapVercelHandler('POST', handleExportHtml);

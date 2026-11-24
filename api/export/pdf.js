import { handleExportPdf, wrapVercelHandler } from '../../src/apiHandlers.js';

export default wrapVercelHandler('POST', handleExportPdf);

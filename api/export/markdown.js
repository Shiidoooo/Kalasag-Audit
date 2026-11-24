import { handleExportMarkdown, wrapVercelHandler } from '../../src/apiHandlers.js';

export default wrapVercelHandler('POST', handleExportMarkdown);

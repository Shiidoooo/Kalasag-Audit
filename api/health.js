import { handleHealth, wrapVercelHandler } from '../src/apiHandlers.js';

export default wrapVercelHandler('GET', handleHealth);

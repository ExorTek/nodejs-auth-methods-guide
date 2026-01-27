import { generateRequestId } from '../utils/helpers.js';

const expressRequestId = (req, res, next) => {
  req.id = generateRequestId();
  next();
};

const fastifyRequestId = () => generateRequestId();

export { expressRequestId, fastifyRequestId };

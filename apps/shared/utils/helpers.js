import { nanoid } from 'nanoid';

const capitalizeFirstLetter = string => string.charAt(0).toUpperCase() + string.slice(1);

const getDuplicateKeyErrorMessage = (errMessage, keyValue) => {
  if (keyValue) {
    const key = capitalizeFirstLetter(Object.keys(keyValue)[0]);
    return `${key} already exists!`;
  } else {
    const splitMessage = errMessage.split(':')[3]?.split(' ')[2];
    return splitMessage
      ? `${capitalizeFirstLetter(splitMessage)} already exist!`
      : 'Duplicate key error! Please Enter a unique key.';
  }
};

const generateRequestId = (length = 16, prefix = '') => `${prefix}${nanoid(length)}`;

export { capitalizeFirstLetter, getDuplicateKeyErrorMessage, generateRequestId };

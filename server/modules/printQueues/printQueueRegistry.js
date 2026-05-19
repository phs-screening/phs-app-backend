const printQueueRegistry = {
  doctorPdf: {
    key: 'doctorPdf',
    collection: 'docPdfQueue',
    includeDoctorName: true,
    validateObjectId: false,
  },
  formA: {
    key: 'formA',
    collection: 'formAPdfQueue',
    includeDoctorName: false,
    validateObjectId: true,
  },
};

function getPrintQueue(queueKey) {
  return printQueueRegistry[queueKey] || null;
}

module.exports = { printQueueRegistry, getPrintQueue };

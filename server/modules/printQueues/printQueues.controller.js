function sendServiceResult(res, result) {
  return res.status(result.status).json(result.body);
}

function createPrintQueuesController({ printQueuesService }) {
  function handleError(res, e) {
    return res.status(500).json({ result: false, error: e.message });
  }

  async function getDoctorPdfQueue(req, res) {
    try {
      const result = await printQueuesService.listQueue(
        "doctorPdf",
        false,
        req.query,
      );
      return sendServiceResult(res, result);
    } catch (e) {
      return handleError(res, e);
    }
  }

  async function getPrintedDoctorPdfQueue(req, res) {
    try {
      const result = await printQueuesService.listQueue(
        "doctorPdf",
        true,
        req.query,
      );
      return sendServiceResult(res, result);
    } catch (e) {
      return handleError(res, e);
    }
  }

  async function addDoctorPdfQueue(req, res) {
    try {
      const result = await printQueuesService.addToQueue("doctorPdf", req.body);
      return sendServiceResult(res, result);
    } catch (e) {
      return handleError(res, e);
    }
  }

  async function markDoctorPdfPrinted(req, res) {
    try {
      const result = await printQueuesService.markAsPrinted(
        "doctorPdf",
        req.params.id,
      );
      return sendServiceResult(res, result);
    } catch (e) {
      return handleError(res, e);
    }
  }

  async function deleteDoctorPdfQueue(req, res) {
    try {
      const result = await printQueuesService.deleteFromQueue(
        "doctorPdf",
        req.params.id,
      );
      return sendServiceResult(res, result);
    } catch (e) {
      return handleError(res, e);
    }
  }

  async function getFormAQueue(req, res) {
    try {
      const result = await printQueuesService.listQueue(
        "formA",
        false,
        req.query,
      );
      return sendServiceResult(res, result);
    } catch (e) {
      return handleError(res, e);
    }
  }

  async function getPrintedFormAQueue(req, res) {
    try {
      const result = await printQueuesService.listQueue(
        "formA",
        true,
        req.query,
      );
      return sendServiceResult(res, result);
    } catch (e) {
      return handleError(res, e);
    }
  }

  async function addFormAQueue(req, res) {
    try {
      const result = await printQueuesService.addToQueue("formA", req.body);
      return sendServiceResult(res, result);
    } catch (e) {
      return handleError(res, e);
    }
  }

  async function markFormAPrinted(req, res) {
    try {
      const result = await printQueuesService.markAsPrinted(
        "formA",
        req.params.id,
      );
      return sendServiceResult(res, result);
    } catch (e) {
      return handleError(res, e);
    }
  }

  async function deleteFormAQueue(req, res) {
    try {
      const result = await printQueuesService.deleteFromQueue(
        "formA",
        req.params.id,
      );
      return sendServiceResult(res, result);
    } catch (e) {
      return handleError(res, e);
    }
  }

  return {
    getDoctorPdfQueue,
    getPrintedDoctorPdfQueue,
    addDoctorPdfQueue,
    markDoctorPdfPrinted,
    deleteDoctorPdfQueue,
    getFormAQueue,
    getPrintedFormAQueue,
    addFormAQueue,
    markFormAPrinted,
    deleteFormAQueue,
  };
}

module.exports = createPrintQueuesController;

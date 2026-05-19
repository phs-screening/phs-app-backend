function sendServiceResult(res, result) {
  return res.status(result.status).json(result.body);
}

function createPatientsController({ patientsService }) {
  async function createPatient(req, res) {
    try {
      const result = await patientsService.createPatient(req.body, req.user);
      return sendServiceResult(res, result);
    } catch (e) {
      return res.status(500).json({ result: false, error: e.message });
    }
  }

  async function getPatient(req, res) {
    const id = parseInt(req.params.id, 10);
    const collection = req.query.collection;

    try {
      const result = await patientsService.getPatientRecord(id, collection);
      return sendServiceResult(res, result);
    } catch (e) {
      return res.status(500).json({ result: false, error: e.message });
    }
  }

  async function getPatientNames(req, res) {
    try {
      const result = await patientsService.getPatientNames();
      return sendServiceResult(res, result);
    } catch (e) {
      return res.status(500).json({ result: false, error: e.message });
    }
  }

  async function getPatientByInitials(req, res) {
    const patientName = req.params.initials;
    const collection = req.query.collection || 'patients';

    try {
      const result = await patientsService.getPatientByInitials(patientName, collection);
      return sendServiceResult(res, result);
    } catch (e) {
      return res.status(500).json({ result: false, error: e.message });
    }
  }

  async function searchPatients(req, res) {
    const patientName = req.query.initials;

    try {
      const result = await patientsService.getPatientByInitials(patientName, 'patients');
      return sendServiceResult(res, result);
    } catch (e) {
      return res.status(500).json({ result: false, error: e.message });
    }
  }

  async function getPatientFormsStatus(req, res) {
    const patientId = parseInt(req.params.id, 10);

    try {
      const result = await patientsService.getPatientFormsStatus(patientId);
      return sendServiceResult(res, result);
    } catch (e) {
      return res.status(500).json({ result: false, error: e.message });
    }
  }

  return {
    createPatient,
    getPatient,
    getPatientNames,
    getPatientByInitials,
    searchPatients,
    getPatientFormsStatus,
  };
}

module.exports = createPatientsController;

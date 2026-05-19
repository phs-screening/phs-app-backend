function sendServiceResult(res, result) {
  return res.status(result.status).json(result.body);
}

function createFormsController({ formsService }) {
  async function submitForm(req, res) {
    const formCollection = req.params.formCollection;
    const patientId = parseInt(req.params.patientId);
    const payload = req.body?.data || {};

    try {
      const result = await formsService.submitForm(formCollection, patientId, payload, req.user);
      return sendServiceResult(res, result);
    } catch (e) {
      return res.status(500).json({ result: false, error: e.message });
    }
  }

  async function submitFormByKey(req, res) {
    const patientId = parseInt(req.params.patientId, 10);
    const formKey = req.params.formKey;
    const payload = req.body?.data || {};

    try {
      const result = await formsService.submitFormByKey(formKey, patientId, payload, req.user);
      return sendServiceResult(res, result);
    } catch (e) {
      return res.status(500).json({ result: false, error: e.message });
    }
  }

  async function getInfo(req, res) {
    const result = formsService.getInfo();
    return sendServiceResult(res, result);
  }

  async function getRegistry(req, res) {
    const result = formsService.getRegistry();
    return sendServiceResult(res, result);
  }

  async function getStatus(req, res) {
    const id = parseInt(req.params.id, 10);

    try {
      const result = await formsService.getStatus(id);
      return sendServiceResult(res, result);
    } catch (e) {
      return res.status(500).json({ result: false, error: e.message });
    }
  }

  async function getPatientForms(req, res) {
    const id = parseInt(req.params.id, 10);

    try {
      const result = await formsService.getPatientForms(id);
      return sendServiceResult(res, result);
    } catch (e) {
      return res.status(500).json({ result: false, error: e.message });
    }
  }

  async function getPatientForm(req, res) {
    const id = parseInt(req.params.id, 10);
    const form = req.params.form;

    try {
      const result = await formsService.getPatientForm(id, form);
      return sendServiceResult(res, result);
    } catch (e) {
      return res.status(500).json({ result: false, error: e.message });
    }
  }

  async function getPatientFormByKey(req, res) {
    const id = parseInt(req.params.patientId, 10);
    const formKey = req.params.formKey;

    try {
      const result = await formsService.getPatientFormByKey(id, formKey);
      return sendServiceResult(res, result);
    } catch (e) {
      return res.status(500).json({ result: false, error: e.message });
    }
  }

  async function upsertPatientForm(req, res) {
    const id = parseInt(req.params.id, 10);
    const form = req.params.form;
    const formData = req.body?.form_data;

    try {
      const result = await formsService.upsertPatientForm(id, form, formData, req.user);
      return sendServiceResult(res, result);
    } catch (e) {
      return res.status(500).json({ result: false, error: e.message });
    }
  }

  return {
    submitForm,
    submitFormByKey,
    getInfo,
    getRegistry,
    getStatus,
    getPatientForms,
    getPatientForm,
    getPatientFormByKey,
    upsertPatientForm,
  };
}

module.exports = createFormsController;

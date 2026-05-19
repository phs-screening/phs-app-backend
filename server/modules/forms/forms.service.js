const { getFormDefinition, getFormInfo, getFormRegistryInfo } = require('./formRegistry');

function createFormsService({ formsRepository }) {
  async function submitForm(formCollection, patientId, payload, user) {
    if (Number.isNaN(patientId)) {
      return { status: 400, body: { result: false, error: 'Invalid patient id' } };
    }

    const patient = await formsRepository.findPatientByQueueNo(patientId);
    if (!patient) {
      return { status: 404, body: { result: false, error: 'Patient not found' } };
    }

    if (patient[formCollection] === undefined) {
      await formsRepository.insertFormDocument(formCollection, patientId, payload);

      await formsRepository.updatePatient(
        patientId,
        { $set: { [formCollection]: patientId } }
      );

      await applyPatientSideEffects(formCollection, patientId, payload);

      return { status: 200, body: { result: true } };
    }

    if (user.is_admin) {
      const updatedPayload = {
        ...payload,
        lastEdited: new Date(),
        lastEditedBy: user.email
      };

      await formsRepository.updateFormDocument(formCollection, patientId, updatedPayload);
      await applyPatientSideEffects(formCollection, patientId, payload);

      return { status: 200, body: { result: true } };
    }

    const errorMsg = 'This form has already been submitted. If you need to make any changes, please contact the admin.';
    return { status: 403, body: { result: false, error: errorMsg } };
  }

  async function submitFormByKey(formKey, patientId, payload, user) {
    const form = getFormDefinition(formKey);
    if (!form) {
      return { status: 404, body: { result: false, error: 'Unknown form' } };
    }

    return submitForm(form.collection, patientId, payload, user);
  }

  async function applyPatientSideEffects(formCollection, patientId, payload) {
    if (formCollection === 'registrationForm') {
      await formsRepository.updatePatient(
        patientId,
        {
          $set: {
            initials: payload.registrationQ2,
            age: payload.registrationQ4
          }
        }
      );
    }

    if (formCollection === 'geriAmtForm') {
      const eligibleForGrace = payload.geriAmtQ12 === 'Yes (Eligible for G-RACE)';
      await formsRepository.updatePatient(
        patientId,
        { $set: { isEligibleForGrace: eligibleForGrace } }
      );
    }
  }

  function getInfo() {
    return { status: 200, body: { result: true, data: getFormInfo() } };
  }

  function getRegistry() {
    return { status: 200, body: { result: true, data: getFormRegistryInfo() } };
  }

  async function getStatus(id) {
    if (Number.isNaN(id)) {
      return { status: 400, body: { result: false, error: 'Bad id' } };
    }

    const patient = await formsRepository.findPatientByQueueNo(id);
    if (!patient) {
      return { status: 404, body: { result: false, error: 'Not found' } };
    }

    const status = Object.fromEntries(
      Object.entries(patient).filter(([k, v]) => k.endsWith('Form')).map(([k]) => [k, true])
    );
    return { status: 200, body: { result: true, data: status } };
  }

  async function getPatientForms(id) {
    if (Number.isNaN(id)) {
      return { status: 400, body: { result: false, error: 'Bad id' } };
    }

    const patient = await formsRepository.findPatientByQueueNo(id);
    if (!patient) {
      return { status: 404, body: { result: false, error: 'Not found' } };
    }

    const formKeys = Object.keys(patient).filter(k => k.endsWith('Form'));
    const out = {};
    for (const fk of formKeys) {
      const doc = await formsRepository.findFormDocument(fk, id);
      if (doc) out[fk] = doc;
    }

    return { status: 200, body: { result: true, data: out } };
  }

  async function getPatientForm(id, form) {
    if (Number.isNaN(id) || !form) {
      return { status: 400, body: { result: false, error: 'Bad request' } };
    }

    const doc = await formsRepository.findFormDocument(form, id);
    return { status: 200, body: { result: true, data: doc } };
  }

  async function getPatientFormByKey(id, formKey) {
    if (Number.isNaN(id) || !formKey) {
      return { status: 400, body: { result: false, error: 'Bad request' } };
    }

    const form = getFormDefinition(formKey);
    if (!form) {
      return { status: 404, body: { result: false, error: 'Unknown form' } };
    }

    const doc = await formsRepository.findFormDocument(form.collection, id);
    return { status: 200, body: { result: true, data: doc } };
  }

  async function upsertPatientForm(id, form, formData, user) {
    if (Number.isNaN(id) || !form) {
      return { status: 400, body: { result: false, error: 'Bad request' } };
    }

    const parsed = typeof formData === 'string' ? JSON.parse(formData) : formData;

    await formsRepository.upsertFormDocument(form, id, parsed, user.email);
    await formsRepository.updatePatient(
      id,
      { $set: { [form]: id } }
    );

    return { status: 200, body: { result: true } };
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

module.exports = createFormsService;

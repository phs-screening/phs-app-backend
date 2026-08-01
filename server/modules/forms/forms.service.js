const {
  getFormDefinition,
  getFormInfo,
  getFormRegistryInfo,
} = require("./formRegistry");
const { applyFormDerivations } = require("./formDerivations");
const {
  STATION_PROJECTION_VERSION,
  extractEligibilityInput,
} = require("../stations/stationProjection");
const { withRetry } = require("../../utils/retry");

function createFormsService({
  formsRepository,
  onFormSubmitted,
  onFormAReadyCheck,
  preparePatientProjection,
}) {
  async function recalculateStationCounts(patient) {
    if (!onFormSubmitted) {
      return;
    }

    try {
      await withRetry(() => onFormSubmitted(patient));
    } catch (error) {
      console.error(
        `Failed to recalculate station counts for patient ${patient.queueNo}:`,
        error,
      );
      throw error;
    }
  }

  async function maybeEnqueueFormA(patient) {
    if (!onFormAReadyCheck) {
      return;
    }

    try {
      await onFormAReadyCheck(patient);
    } catch (error) {
      console.error(
        `Failed to check Form A queue readiness for patient ${patient.queueNo}:`,
        error,
      );
    }
  }

  async function ensureProjection(patient) {
    return preparePatientProjection ? preparePatientProjection(patient) : patient;
  }

  function buildPatientUpdate(formCollection, patientId, payload) {
    const set = { [formCollection]: patientId };

    if (formCollection === "registrationForm") {
      set.initials = payload.registrationQ2;
      set.age = payload.registrationQ4;
    }

    if (formCollection === "geriAmtForm") {
      set.isEligibleForGrace =
        payload.geriAmtQ12 === "Yes (Eligible for G-RACE)";
    }

    const eligibilityInput = extractEligibilityInput(formCollection, payload);
    if (eligibilityInput) {
      set[`stationEligibilityInputs.${eligibilityInput.alias}`] = eligibilityInput.data;
      set.stationProjectionVersion = STATION_PROJECTION_VERSION;
    }

    return {
      $set: set,
      $inc: { stationProjectionRevision: 1 },
    };
  }

  async function finalizeFormSave(formCollection, patientId, payload) {
    const updatedPatient = await withRetry(() =>
      formsRepository.updatePatientAfterForm(
        patientId,
        buildPatientUpdate(formCollection, patientId, payload),
      ),
    );
    if (!updatedPatient) {
      throw new Error(`Patient ${patientId} disappeared while saving ${formCollection}`);
    }

    await recalculateStationCounts(updatedPatient);
    await maybeEnqueueFormA(updatedPatient);
    return updatedPatient;
  }

  async function repairPatientDerivedState(patient) {
    await recalculateStationCounts(patient);
    await maybeEnqueueFormA(patient);
  }

  function duplicateSubmissionResult() {
    const errorMsg =
      "This form has already been submitted. If you need to make any changes, please contact the admin.";
    return { status: 409, body: { result: false, error: errorMsg } };
  }

  async function submitForm(formCollection, patientId, payload, user) {
    if (Number.isNaN(patientId)) {
      return {
        status: 400,
        body: { result: false, error: "Invalid patient id" },
      };
    }

    let patient = await formsRepository.findPatientByQueueNo(patientId);
    if (!patient) {
      return {
        status: 404,
        body: { result: false, error: "Patient not found" },
      };
    }

    const projectionNeededRepair = Boolean(patient.stationProjectionNeedsRepair);
    patient = await ensureProjection(patient);
    const payloadWithDerivations = applyFormDerivations(formCollection, payload);

    if (patient[formCollection] === undefined) {
      try {
        await formsRepository.insertFormDocument(
          formCollection,
          patientId,
          payloadWithDerivations,
        );
      } catch (error) {
        if (error?.code !== 11000) throw error;

        const canonicalForm = await formsRepository.findFormDocument(
          formCollection,
          patientId,
        );
        if (!canonicalForm) {
          throw new Error(
            `Duplicate ${formCollection} exists for patient ${patientId}, but the canonical form could not be loaded`,
          );
        }

        await finalizeFormSave(formCollection, patientId, canonicalForm);
        return duplicateSubmissionResult();
      }

      await finalizeFormSave(
        formCollection,
        patientId,
        payloadWithDerivations,
      );

      return { status: 200, body: { result: true } };
    }

    if (user.is_admin) {
      const updatedPayload = {
        ...payloadWithDerivations,
        lastEdited: new Date(),
        lastEditedBy: user.email,
      };

      await formsRepository.updateFormDocument(
        formCollection,
        patientId,
        updatedPayload,
      );
      await finalizeFormSave(formCollection, patientId, updatedPayload);

      return { status: 200, body: { result: true } };
    }

    if (projectionNeededRepair) {
      await repairPatientDerivedState(patient);
    }

    return duplicateSubmissionResult();
  }

  async function submitFormByKey(formKey, patientId, payload, user) {
    const form = getFormDefinition(formKey);
    if (!form) {
      return { status: 404, body: { result: false, error: "Unknown form" } };
    }

    return submitForm(form.collection, patientId, payload, user);
  }

  function getInfo() {
    return { status: 200, body: { result: true, data: getFormInfo() } };
  }

  function getRegistry() {
    return { status: 200, body: { result: true, data: getFormRegistryInfo() } };
  }

  async function getStatus(id) {
    if (Number.isNaN(id)) {
      return { status: 400, body: { result: false, error: "Bad id" } };
    }

    const patient = await formsRepository.findPatientByQueueNo(id);
    if (!patient) {
      return { status: 404, body: { result: false, error: "Not found" } };
    }

    const status = Object.fromEntries(
      Object.entries(patient)
        .filter(([k, v]) => k.endsWith("Form"))
        .map(([k]) => [k, true]),
    );
    return { status: 200, body: { result: true, data: status } };
  }

  async function getPatientForms(id) {
    if (Number.isNaN(id)) {
      return { status: 400, body: { result: false, error: "Bad id" } };
    }

    const patient = await formsRepository.findPatientByQueueNo(id);
    if (!patient) {
      return { status: 404, body: { result: false, error: "Not found" } };
    }

    const formKeys = Object.keys(patient).filter((k) => k.endsWith("Form"));
    const out = {};
    for (const fk of formKeys) {
      const doc = await formsRepository.findFormDocument(fk, id);
      if (doc) out[fk] = doc;
    }

    return { status: 200, body: { result: true, data: out } };
  }

  async function getPatientForm(id, form) {
    if (Number.isNaN(id) || !form) {
      return { status: 400, body: { result: false, error: "Bad request" } };
    }

    const doc = await formsRepository.findFormDocument(form, id);
    return { status: 200, body: { result: true, data: doc } };
  }

  async function getPatientFormByKey(id, formKey) {
    if (Number.isNaN(id) || !formKey) {
      return { status: 400, body: { result: false, error: "Bad request" } };
    }

    const form = getFormDefinition(formKey);
    if (!form) {
      return { status: 404, body: { result: false, error: "Unknown form" } };
    }

    const doc = await formsRepository.findFormDocument(form.collection, id);
    return { status: 200, body: { result: true, data: doc } };
  }

  async function upsertPatientForm(id, form, formData, user) {
    if (Number.isNaN(id) || !form) {
      return { status: 400, body: { result: false, error: "Bad request" } };
    }

    const parsed =
      typeof formData === "string" ? JSON.parse(formData) : formData;
    const parsedWithDerivations = applyFormDerivations(form, parsed);

    let patient = await formsRepository.findPatientByQueueNo(id);
    if (!patient) {
      return { status: 404, body: { result: false, error: "Patient not found" } };
    }
    patient = await ensureProjection(patient);

    await formsRepository.upsertFormDocument(form, id, parsedWithDerivations, user.email);
    await finalizeFormSave(form, id, parsedWithDerivations);

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

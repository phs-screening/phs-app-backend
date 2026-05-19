const formRegistry = {
  registrationForm: { key: 'registrationForm', title: 'Registration', collection: 'registrationForm' },
  triageForm: { key: 'triageForm', title: 'Triage', collection: 'triageForm' },
};

function getFormInfo() {
  return Object.fromEntries(
    Object.entries(formRegistry).map(([key, form]) => [
      key,
      { key: form.key, title: form.title },
    ])
  );
}

module.exports = { formRegistry, getFormInfo };

const defaultTemplates = require("./sms.templates");

function createTemplateError(message, code) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function getApprovedTemplate(
  templateKey,
  language,
  templates = defaultTemplates,
) {
  const definition = templates[templateKey];
  if (!definition) {
    throw createTemplateError("Unknown SMS template", "SMS_TEMPLATE_UNKNOWN");
  }
  if (!definition.approved) {
    throw createTemplateError(
      "SMS template is not approved",
      "SMS_TEMPLATE_NOT_APPROVED",
    );
  }

  const template = definition.languages?.[language];
  if (!template) {
    throw createTemplateError(
      "SMS language template is unavailable",
      "SMS_TEMPLATE_LANGUAGE_MISSING",
    );
  }
  if (
    !Number.isFinite(definition.maximumCharacters) ||
    definition.maximumCharacters <= 0
  ) {
    throw createTemplateError(
      "SMS template character limit is not configured",
      "SMS_TEMPLATE_LIMIT_MISSING",
    );
  }

  return { definition, template };
}

function renderSmsTemplate({
  templateKey,
  templateVersion,
  language,
  variables,
  templates = defaultTemplates,
}) {
  const { definition, template } = getApprovedTemplate(
    templateKey,
    language,
    templates,
  );
  if (templateVersion && definition.version !== templateVersion) {
    throw createTemplateError(
      "SMS template version does not match the planned reminder",
      "SMS_TEMPLATE_VERSION_MISMATCH",
    );
  }

  const requiredVariables = definition.requiredVariables || [];
  const allowedVariables = new Set(requiredVariables);
  for (const key of Object.keys(variables || {})) {
    if (!allowedVariables.has(key)) {
      throw createTemplateError(
        "Unexpected SMS template variable",
        "SMS_TEMPLATE_VARIABLE_UNEXPECTED",
      );
    }
  }

  let message = template;
  for (const key of requiredVariables) {
    const value = variables?.[key];
    if (value === undefined || value === null || String(value).trim() === "") {
      throw createTemplateError(
        "Required SMS template variable is missing",
        "SMS_TEMPLATE_VARIABLE_MISSING",
      );
    }
    message = message.replaceAll(`{{${key}}}`, String(value));
  }

  if (/{{[^{}]+}}/.test(message)) {
    throw createTemplateError(
      "SMS template contains an unresolved variable",
      "SMS_TEMPLATE_VARIABLE_UNRESOLVED",
    );
  }
  if (message.length > definition.maximumCharacters) {
    throw createTemplateError(
      "Rendered SMS exceeds the approved character limit",
      "SMS_TEMPLATE_TOO_LONG",
    );
  }

  return {
    message,
    templateVersion: definition.version,
  };
}

module.exports = {
  getApprovedTemplate,
  renderSmsTemplate,
};

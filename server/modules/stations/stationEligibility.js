function getEligibilityRows(forms = {}) {
  const {
    reg = {},
    pmhx = {},
    hxsocial = {},
    hxgynae = {},
    triage = {},
    hcsr = {},
    hxoral = {},
    phq = {},
    hxm4m5 = {},
    ophthal = {},
  } = forms;

  const createData = (name, isEligible) => ({
    name,
    eligibility: isEligible ? 'YES' : 'NO',
  });

  const isVaccinationEligible = reg?.registrationQ4 >= 65;
  const isHealthierSGEligible = reg?.registrationQ11 !== 'Yes';
  const isLungFunctionEligible =
    reg?.registrationQ21 === 'Yes' &&
    hxsocial?.SOCIAL16 === 'Yes' &&
    (hxsocial?.SOCIAL10 === 'Yes' || hxsocial?.SOCIAL11 === 'Yes');
  const isWomenCancerEducationEligible = reg?.registrationQ5 === 'Female';
  const isPodiatryEligible = pmhx?.PMHX5?.includes('Diabetes/Pre-Diabetic');
  const isMentalHealthEligible =
    (phq?.PHQ10 >= 10 && reg?.registrationQ4 < 60) || phq?.PHQ11 === 'Yes';
  const isMammobusEligible = reg.registrationQ19 === 'Yes';
  const isHPVEligible =
    (hxgynae?.GYNAE12 === '5 years or longer' || hxgynae?.GYNAE12 === 'Never before') &&
    hxgynae?.GYNAE14 === 'Yes' &&
    hxgynae?.GYNAE15 === 'No' &&
    (hxgynae?.GYNAE13 === '3 years or longer' || hxgynae?.GYNAE13 === 'Never before') &&
    hxgynae?.GYNAE16 === 'Yes';
  const isAudiometryEligible = reg?.registrationQ4 >= 60 && hcsr?.hxHcsrQ5 === 'No';
  const isGeriatricScreeningEligible = reg?.registrationQ4 >= 60;
  const isOphthalmologyEligible = reg?.registrationQ4 >= 60 || hcsr?.hxHcsrQ3 === 'Yes';

  const isDoctorStationEligible =
    hxm4m5?.hxM4M5Q1 === 'Yes' &&
    (triage?.triageQ9 === 'Yes' ||
      hcsr?.hxHcsrQ7 === 'Yes' ||
      hcsr?.hxHcsrQ6 === 'Yes' ||
      pmhx?.PMHX7 === 'Yes' ||
      phq?.PHQ10 >= 10 ||
      phq?.PHQ9 == '1 - Several days' ||
      phq?.PHQ9 == '2 - More than half the days' ||
      phq?.PHQ9 == '3 - Nearly everyday');

  ophthal?.OphthalQ9?.includes("Referred to Doctor's Station");

  const isDietitianEligible =
    pmhx?.PMHX5?.includes('Hypertension') ||
    pmhx?.PMHX5?.includes('Hyperlipidemia') ||
    pmhx?.PMHX5?.includes('Diabetes/Pre-Diabetic') ||
    pmhx?.PMHX5?.includes('Kidney Disease') ||
    pmhx?.PMHX5?.includes('Heart disease') ||
    pmhx?.PMHX5?.includes('Others');
  const isSocialServicesEligible =
    hxsocial?.SOCIAL6 === 'Yes' ||
    hxsocial?.SOCIAL7 === 'Yes' ||
    (hxsocial?.SOCIAL8 === 'Yes' && hxsocial?.SOCIAL9 === 'No') ||
    ophthal?.OphthalQ13 === 'Yes';

  const isDentalEligible =
    pmhx?.PMHX5?.includes('Diabetes/Pre-Diabetic') ||
    hxsocial?.SOCIAL10 === 'Yes' ||
    hxsocial?.SOCIAL11 === 'Yes' ||
    hxoral?.ORAL1 === 'Poor' ||
    hxoral?.ORAL2 === 'Yes' ||
    hxoral?.ORAL3 === 'Yes' ||
    hxoral?.ORAL4 === 'No' ||
    hxoral?.ORAL5 === 'Yes';

  return [
    createData('Healthier SG Booth', isHealthierSGEligible),
    createData('Lung Function Testing', isLungFunctionEligible),
    createData("Women's Cancer Education", isWomenCancerEducationEligible),
    createData('Podiatry', isPodiatryEligible),
    createData("Nutritionist's/Dietitian's Consult", isDietitianEligible),
    createData('Geriatric Screening', isGeriatricScreeningEligible),
    createData('Ophthalmology', isOphthalmologyEligible),
    createData('Oral Health', isDentalEligible),
    createData('Social Services', isSocialServicesEligible),
    createData('Mental Health', isMentalHealthEligible),
    createData('Mammobus', isMammobusEligible),
    createData('HPV On-Site Testing', isHPVEligible),
    createData('Audiometry', isAudiometryEligible),
    createData('Vaccination', isVaccinationEligible),
    createData("Doctor's Station", isDoctorStationEligible),
  ];
}

function getEligibleStationNames(forms = {}) {
  return getEligibilityRows(forms)
    .filter((row) => row.eligibility === 'YES')
    .map((row) => row.name);
}

module.exports = { getEligibilityRows, getEligibleStationNames };

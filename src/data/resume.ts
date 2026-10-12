export const profile = {
  name: 'Nirmala NB',
  role: 'Cyber Security Engineer',
  now: 'Security sign-off at Emirates NBD, Dubai. Studying for the OSCP in the evenings.',
  tagline: 'I find the holes in banking software before someone else does.',
  summary:
    'Four years in banking, from network and firewall governance to application, API and vulnerability testing. I embed security into the full delivery lifecycle, working with development, risk, storage and infrastructure teams, and give the go/no-go on code, pipelines and releases. Lately that includes security-testing LLM integrations before they ship.',
  location: 'Dubai, UAE',
  phone: '+971-552689912',
  email: 'nbnirmala1999@gmail.com',
  linkedin: 'linkedin.com/in/nirmala-nb',
  linkedinUrl: 'https://linkedin.com/in/nirmala-nb',
};

// Single source of truth for contact details — used by the intro and the footer.
export interface ContactLink {
  label: string;
  value: string;
  href: string;
  external?: boolean;
}

export const contactLinks: ContactLink[] = [
  { label: 'Email', value: profile.email, href: `mailto:${profile.email}` },
  { label: 'Phone', value: profile.phone, href: `tel:${profile.phone.replace(/[^+\d]/g, '')}` },
  { label: 'LinkedIn', value: 'in/nirmala-nb', href: profile.linkedinUrl, external: true },
];

// Pull-quote removed — the Activ Bytes achievement is rendered in the Experience section below.
export interface Role {
  title: string;
  company: string;
  place: string;
  period: string;
  current?: boolean;
  points: string[];
}

export const experience: Role[] = [
  {
    title: 'Security Assessor',
    company: 'Emirates NBD',
    place: 'Dubai',
    period: 'Apr 2026 — Present',
    current: true,
    points: [
      'Review firewall change requests (port, service, protocol, source, destination, justification) on least-privilege and segmentation principles, assess wireless requests, and troubleshoot Linux and infrastructure issues across pre-production and production.',
      'Assess banking applications end to end — container and proxy through the BFF to core services — covering API security (authentication, authorization, data exposure, input validation) and the internal API gateways routing traffic across the organization.',
      'Perform application security testing and secure code review with development and risk teams, review CI/CD pipeline changes, code and dependency upgrades, and give the security sign-off on code, pipelines and releases before go-live.',
      'Review Kafka topics for access control, data sensitivity and secure transport; cover the database lifecycle through encryption at rest and in transit; define secrets management rules and check storage configurations against baselines with the storage team.',
      'Review third-party integrations for data flow, API exposure and vendor risk, security-test LLMs before AI integration, analyze organization-level AI risk (data leakage, prompt injection, model misuse) and run package and malware analysis.',
      'Run pre-production security reviews against the bank baseline, verify ELK logging and monitoring, confirm scans are remediated or risk-accepted, and give the final go-live sign-off; investigate P1 incidents, support hotfixes and document on Confluence.',
    ],
  },
  {
    title: 'Lead Security Analyst',
    company: 'ActivGreen',
    place: 'Trivandrum',
    period: 'Dec 2025 — Apr 2026',
    points: [
      'Led vulnerability assessments and penetration tests across enterprise applications, infrastructure and networks, including onsite engagements in Dubai, and assessed networks with Nmap, Nessus and Nexpose.',
      'Triaged application security incidents with development teams, traced root cause, pushed WAF rule updates to prevent repeat attempts, scored findings by CVSS and validated the fixes.',
      'Tested Android and iOS apps and Android SDKs for insecure storage, session handling and certificate pinning, reviewed third-party vendor data flows and assessed AWS, Azure and GCP for misconfigurations.',
    ],
  },
  {
    title: 'Security Consultant',
    company: 'Activ Bytes',
    place: 'Trivandrum',
    period: 'Mar 2023 — Nov 2025',
    points: [
      'Ran manual penetration tests on web and API systems and found 50+ critical and high-risk issues including authentication bypass, IDOR and RCE, mapped to OWASP Top 10 and the API Security Top 10.',
      'Performed secure code review, CI/CD pipeline reviews and threat modeling with development teams, finding security loopholes early and driving remediation before release.',
      'Security-tested LLM-backed features and reviewed AI integrations for prompt injection and data leakage risk, verifying authentication, storage and transport findings from MobSF APK scans.',
      'Wrote risk-based reports covering business impact, CVSS severity, remediation and validation, and ran purple team engagements onsite in Abu Dhabi with SOC detection and response teams.',
    ],
  },
  {
    title: 'VAPT Executive',
    company: 'SIDR Solutions',
    place: 'Mumbai',
    period: 'Aug 2022 — Feb 2023',
    points: [
      'Performed vulnerability assessments and penetration tests for enterprise clients, including ATM security testing with hard disk imaging and malware analysis.',
    ],
  },
];

export interface SkillGroup {
  label: string;
  skills: string[];
}

export const skillGroups: SkillGroup[] = [
  {
    label: 'Application & API Security',
    skills: [
      'OWASP Top 10',
      'OWASP API Security Top 10',
      'OWASP LLM Top 10',
      'SAST',
      'DAST',
      'SCA',
      'Secure code review',
      'Security design review',
      'Threat modeling',
      'API gateway security',
      'CVSS scoring',
      'Mobile application security',
    ],
  },
  {
    label: 'Infrastructure, Cloud & Data Security',
    skills: [
      'VM & server hardening',
      'Firewall & segmentation review',
      'Least privilege',
      'CI/CD security',
      'Container security',
      'Secrets management',
      'Encryption at rest & in transit',
      'Kafka security',
      'Linux',
    ],
  },
  {
    label: 'Governance, Risk & Response',
    skills: [
      'Secure SDLC',
      'DevSecOps',
      'Third-party & vendor risk',
      'AI/LLM security',
      'Change management',
      'Incident response',
      'Incident triage & root-cause analysis',
      'Malware analysis',
      'AWS, Azure & GCP assessment',
      'Android & iOS application testing',
    ],
  },
  {
    label: 'Frameworks, Tools & Scripting',
    skills: [
      'MITRE ATT&CK',
      'PTES',
      'Burp Suite',
      'MobSF',
      'Nessus',
      'Nexpose',
      'Nmap',
      'Checkmarx',
      'DB Compass',
      'Sysdig',
      'LogRhythm',
      'Darktrace',
      'FTK Imager',
      'Python',
      'Bash',
    ],
  },
];

export const education = {
  degree: 'Bachelor of Engineering',
  institution: 'Visvesvaraya Technological University, India',
  year: '2022',
  certs: ['CEH (in progress, expected 2026)', 'OSCP (in preparation)'],
  languages: [
    { name: 'English', level: 'Fluent' },
    { name: 'Malayalam', level: 'Native' },
    { name: 'Kannada', level: 'Native' },
    { name: 'Hindi', level: 'Conversational' },
  ],
};

# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38664 - The system package management tool must verify ownership on all files and directories associated with the audit package.'

control 'V-38664' do
  impact 0.5
  title 'The system package management tool must verify ownership on all files and directories associated with the audit package.'
  desc '
Ownership of audit binaries and configuration files that is incorrect could allow an unauthorized user to gain privileges that they should not have. The ownership set by the vendor should be maintained. Any deviations from this baseline should be investigated.
'
  tag 'stig','V-38664'
  tag severity: 'medium'
  tag checkid: 'C-46224r1_chk'
  tag fixid: 'F-43613r1_fix'
  tag version: 'RHEL-06-000279'
  tag ruleid: 'SV-50465r1_rule'
  tag fixtext: '
The RPM package management system can restore file ownership of the audit package files and directories. The following command will update audit files with ownership different from what is expected by the RPM database:

# rpm --setugids audit
'
  tag checktext: '
The following command will list which audit files on the system have ownership different from what is expected by the RPM database:

# rpm -V audit | grep \'^.....U\'


If there is output, this is a finding.
'

# START_DESCRIBE V-38664
  tag 'rpm','owner'
  describe command("rpm -V audit | grep '^.....U'") do
    its('stdout') { should eq "" }
  end
# END_DESCRIBE V-38664

end

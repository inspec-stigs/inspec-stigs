# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38642 - The system default umask for daemons must be 027 or 022.'

control 'V-38642' do
  impact 0.1
  title 'The system default umask for daemons must be 027 or 022.'
  desc '
The umask influences the permissions assigned to files created by a process at run time. An unnecessarily permissive umask could result in files being created with insecure permissions.
'
  tag 'stig','V-38642'
  tag severity: 'low'
  tag checkid: 'C-46203r1_chk'
  tag fixid: 'F-43592r1_fix'
  tag version: 'RHEL-06-000346'
  tag ruleid: 'SV-50443r1_rule'
  tag fixtext: '
The file "/etc/init.d/functions" includes initialization parameters for most or all daemons started at boot time. The default umask of 022 prevents creation of group- or world-writable files. To set the default umask for daemons, edit the following line, inserting 022 or 027 for [UMASK] appropriately:

umask [UMASK]

Setting the umask to too restrictive a setting can cause serious errors at runtime. Many daemons on the system already individually restrict themselves to a umask of 077 in their own init scripts.
'
  tag checktext: '
To check the value of the "umask", run the following command:

$ grep umask /etc/init.d/functions

The output should show either "022" or "027".
If it does not, this is a finding.
'

# START_DESCRIBE V-38642
  tag 'service','init.d','umask'
  describe.one do
    describe file('/etc/init.d/functions') do
      its('content') { should match '^umask 022$' }
    end
    describe file('/etc/init.d/functions') do
      its('content') { should match '^umask 027$' }
    end
  end

# END_DESCRIBE V-38642

end

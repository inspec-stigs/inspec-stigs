# START_DESCRIBE V-38437
  describe service('autofs') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
# END_DESCRIBE V-38437

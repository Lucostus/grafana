import { setupMockedAPI } from './__mocks__/API';

describe('api', () => {
  describe('describeLogGroup', () => {
    it('replaces region correctly in the query', async () => {
      const { api, resourceRequestMock } = setupMockedAPI();
      await api.describeLogGroups({ region: 'default' });
      expect(resourceRequestMock.mock.calls[0][1].region).toBe('us-west-1');

      await api.describeLogGroups({ region: 'eu-east' });
      expect(resourceRequestMock.mock.calls[1][1].region).toBe('eu-east');
    });

    it('should return log groups as an array of options', async () => {
      const response = [
        {
          text: '/aws/containerinsights/dev303-workshop/application',
          value: '/aws/containerinsights/dev303-workshop/application',
          label: '/aws/containerinsights/dev303-workshop/application',
        },
        {
          text: '/aws/containerinsights/dev303-workshop/flowlogs',
          value: '/aws/containerinsights/dev303-workshop/flowlogs',
          label: '/aws/containerinsights/dev303-workshop/flowlogs',
        },
        {
          text: '/aws/containerinsights/dev303-workshop/dataplane',
          value: '/aws/containerinsights/dev303-workshop/dataplane',
          label: '/aws/containerinsights/dev303-workshop/dataplane',
        },
      ];

      const { api } = setupMockedAPI({ response });
      const expectedLogGroups = [
        {
          text: '/aws/containerinsights/dev303-workshop/application',
          value: '/aws/containerinsights/dev303-workshop/application',
          label: '/aws/containerinsights/dev303-workshop/application',
        },
        {
          text: '/aws/containerinsights/dev303-workshop/flowlogs',
          value: '/aws/containerinsights/dev303-workshop/flowlogs',
          label: '/aws/containerinsights/dev303-workshop/flowlogs',
        },
        {
          text: '/aws/containerinsights/dev303-workshop/dataplane',
          value: '/aws/containerinsights/dev303-workshop/dataplane',
          label: '/aws/containerinsights/dev303-workshop/dataplane',
        },
      ];

      const logGroups = await api.describeLogGroups({ region: 'default' });

      expect(logGroups).toEqual(expectedLogGroups);
    });
  });

  describe('memoization', () => {
    it('should not initiate new api request in case a previous request had same args', async () => {
      const getMock = jest.fn();
      const { api, resourceRequestMock } = setupMockedAPI({ getMock });
      resourceRequestMock.mockResolvedValue([]);
      await Promise.all([
        api.getMetrics('AWS/EC2', 'us-east-1'),
        api.getMetrics('AWS/EC2', 'us-east-1'),
        api.getMetrics('AWS/EC2', 'us-east-2'),
        api.getMetrics('AWS/EC2', 'us-east-2'),
        api.getMetrics('AWS/EC2', 'us-east-2'),
      ]);
      expect(resourceRequestMock).toHaveBeenCalledTimes(2);
    });
  });
});

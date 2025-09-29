import StartPlugin from "@magnolia/cli-start-plugin"
import TrimmPlatformRunnerPlugin from "@technology/cli-tp-runner-plugin"
import JumpstartPlugin from "@magnolia/cli-jumpstart-plugin";

export default {
  analytics: {
    enabled: false,
  },
  // Logger configuration
  // see: https://github.com/winstonjs/winston#logging for logging levels explanation
  logger: {
    filename: '../../../mgnl.error.log',
    fileLevel: 'debug',
    consoleLevel: 'info'
  },
  // Here you can add plugins you want to use with MGNL CLI
  plugins: [
    new JumpstartPlugin(),
    new StartPlugin({
      tomcatPath: '../../../.magnolia/apache-tomcat'
    }),
    new TrimmPlatformRunnerPlugin({
      tomcatPath: './.magnolia/apache-tomcat'
    })
  ]
};

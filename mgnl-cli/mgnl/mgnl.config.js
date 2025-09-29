import StartPlugin from "@magnolia/cli-start-plugin"
import TrimmPlatformRunnerPlugin from "{{ .DevboxProjectDir }}/tp-runner/dist/index.js"
import JumpstartPlugin from "@magnolia/cli-jumpstart-plugin";

export default {
  analytics: {
    enabled: false,
  },
  // Logger configuration
  // see: https://github.com/winstonjs/winston#logging for logging levels explanation
  logger: {
    filename: '{{ .DevboxProjectDir }}/mgnl.error.log',
    fileLevel: 'debug',
    consoleLevel: 'info'
  },
  // Here you can add plugins you want to use with MGNL CLI
  plugins: [
    new JumpstartPlugin(),
    new StartPlugin({
      tomcatPath: '{{ .DevboxProjectDir }}/.magnolia/apache-tomcat'
    }),
    new TrimmPlatformRunnerPlugin({
      tomcatPath: '{{ .DevboxProjectDir }}/.magnolia/apache-tomcat'
    })
  ]
};

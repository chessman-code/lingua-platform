/**
 * 言葉 LINGUA — GitHub 仓库即数据库配置
 * 前端直接通过 GitHub Contents API 读写 data/ 目录下的 JSON 文件
 * 无需后端服务器，无需额外部署
 */
(function() {
  var _c = [103,104,117,95,111,111,75,81,80,120,50,54,113,55,87,82,99,100,76,52,111,67,116,105,83,52,78,72,110,78,114,56,50,116,50,53,114,89,83,84];
  window.LINGUA_CONFIG = {
    ghToken: String.fromCharCode.apply(null, _c),
    ghOwner: 'chessman-code',
    ghRepo: 'lingua-platform',
    ghBranch: 'main',
    ghApi: 'https://api.github.com/repos/chessman-code/lingua-platform',
    rawDataUrl: 'https://raw.githubusercontent.com/chessman-code/lingua-platform/main',
  };
})();

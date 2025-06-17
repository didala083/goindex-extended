/**
 * Cloudflare Workers 入口点
 * 功能：实现Google Drive文件的Web访问接口，支持目录浏览、文件下载和搜索
 * 认证机制：
 *   - 文件下载：可自由设置直接访问文件URL是否要认证
 *   - 目录浏览：需要基本认证（用户名/密码）
 *   - API请求：需要基本认证
 */
export default {
  /**
   * 处理所有传入的HTTP请求
   * @param {Request} request - 传入的请求对象
   * @param {Object} env - Cloudflare Workers环境变量
   */
  async fetch(request, env) {
    // 初始化认证配置和Google Drive实例
    const authConfig = getAuthConfig(env);
    if (gds.length === 0) {
      for (let i = 0; i < authConfig.roots.length; i++) {
        const gd = new googleDrive(authConfig, i);
        await gd.init();
        gds.push(gd);
      }
      let tasks = [];
      gds.forEach(gd => {
        tasks.push(gd.initRootType());
      });
      for (let task of tasks) {
        await task;
      }
    }

    let gd;
    let url = new URL(request.url);
    let path = url.pathname;

    function redirectToIndexPage() {
      return new Response('', {status: 301, headers: {'Location': `${url.origin}/0:/`}});
    }

    if (path == '/') return redirectToIndexPage();
    if (path.toLowerCase() == '/favicon.ico') {
      return new Response('', {status: 404});
    }

    const command_reg = /^\/(?<num>\d+):(?<command>[a-zA-Z0-9]+)$/g;
    const match = command_reg.exec(path);
    if (match) {
      const num = match.groups.num;
      const order = Number(num);
      if (order >= 0 && order < gds.length) {
        gd = gds[order];
      } else {
        return redirectToIndexPage();
      }
      for (const r = gd.basicAuthResponse(request); r;) return r;
      const command = match.groups.command;
      if (command === 'search') {
        if (request.method === 'POST') {
          return handleSearch(request, gd);
        } else {
          const params = url.searchParams;
          return new Response(html(gd.order, {
              q: params.get("q") || '',
              is_search_page: true,
              root_type: gd.root_type
            }, gd.authConfig), {
              status: 200,
              headers: {
                'Content-Type': 'text/html; charset=utf-8',
                'Content-Security-Policy': "default-src 'self' https: 'unsafe-inline' 'unsafe-eval'; img-src 'self' https: data:;",
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'DENY',
                'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
              }
            });
        }
      } else if (command === 'id2path' && request.method === 'POST') {
        return handleId2Path(request, gd);
      }
    }

    const common_reg = /^\/\d+:\/.*$/g;
    try {
      if (!path.match(common_reg)) {
        return redirectToIndexPage();
      }
      let split = path.split("/");
      let order = Number(split[1].slice(0, -1));
      if (order >= 0 && order < gds.length) {
        gd = gds[order];
      } else {
        return redirectToIndexPage();
      }
    } catch (e) {
      return redirectToIndexPage();
    }

    const basic_auth_res = gd.basicAuthResponse(request);
    path = path.replace(gd.url_path_prefix, '') || '/';
    if (request.method == 'POST') {
      return basic_auth_res || apiRequest(request, gd);
    }

    let action = url.searchParams.get('a');
    if (path.substr(-1) == '/' || action != null) {
      return basic_auth_res || new Response(html(gd.order, {root_type: gd.root_type}, gd.authConfig), {
        status: 200,
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Content-Security-Policy': "default-src 'self' https: 'unsafe-inline' 'unsafe-eval'; img-src 'self' https: data:;",
          'X-Content-Type-Options': 'nosniff',
          'X-Frame-Options': 'DENY',
          'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
        }
      });
    } else {
      if (path.split('/').pop().toLowerCase() == ".password") {
        return basic_auth_res || new Response("", {status: 404});
      }
      let file = await gd.file(path);
      let range = request.headers.get('Range');
      const inline_down = 'true' === url.searchParams.get('inline');
      // 根据protect_file_link设置决定是否检查文件下载认证
      if (gd.root.protect_file_link && basic_auth_res) return basic_auth_res;
      return gd.down(file.id, range, inline_down);
    }
  }
};

/**
 * 从环境变量生成认证配置
 * @param {Object} env - Cloudflare Workers环境变量
 * @returns {Object} 认证配置对象
 */
const getAuthConfig = (env) => {
  // 打印环境变量以进行调试
  console.log("环境变量检查:");
  console.log("CLIENT_ID存在:", !!env.CLIENT_ID);
  console.log("CLIENT_SECRET存在:", !!env.CLIENT_SECRET);
  console.log("REFRESH_TOKEN存在:", !!env.REFRESH_TOKEN);
  console.log("BASIC_AUTH_USER存在:", !!env.BASIC_AUTH_USER);
  console.log("BASIC_AUTH_PASS存在:", !!env.BASIC_AUTH_PASS);
  
  return {
    "siteName": "命运之门1",
    "siteIcon": "https://raw.githubusercontent.com/didala083/goindex-extended/blob/master/images/favicon.png",
    "version": "1.15",
    "client_id": env.CLIENT_ID || "",
    "client_secret": env.CLIENT_SECRET || "",
    "refresh_token": env.REFRESH_TOKEN || "",
    "roots": [
      {
        id: "root",
        name: "My Drive",
        user: env.BASIC_AUTH_USER || "",
        pass: env.BASIC_AUTH_PASS || "",
        protect_file_link: true  // 设置为true，确保文件链接受保护需要认证
      }
    ],
    "enable_virus_infected_file_down": false,
    "files_list_page_size": 500,
    "search_result_list_page_size": 50,
    "enable_cors_file_down": false,
    "enable_password_file_verify": false
  };
};

const uiConfig = {
  "theme": "material",
  "dark_mode": true,
  "hide_actions_tab": false,
  "helpURL": "",
  "footer_text": "Made with <3",
  "main_color": "blue-grey",
  "accent_color": "blue"
};

const FUNCS = {
  formatSearchKeyword: function (keyword) {
    let nothing = "";
    let space = " ";
    if (!keyword) return nothing;
    return keyword.replace(/(!=)|['"=<>/\\:]/g, nothing)
      .replace(/[,，|(){}]/g, space)
      .trim()
  }
};

const CONSTS = new (class {
  default_file_fields = 'parents,id,name,mimeType,modifiedTime,createdTime,fileExtension,size';
  gd_root_type = {
    user_drive: 0,
    share_drive: 1,
    sub_folder: 2
  };
  folder_mime_type = 'application/vnd.google-apps.folder';
})();

var gds = [];

function html(current_drive_order = 0, model = {}, authConfig) {
  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0,maximum-scale=1.0, user-scalable=no"/>
  <title>${authConfig.siteName}</title>
  <link rel="shortcut icon" href="${authConfig.siteIcon}" type="image/x-icon" />
  <script>
    window.drive_names = JSON.parse('${JSON.stringify(authConfig.roots.map(it => it.name))}');
    window.MODEL = JSON.parse('${JSON.stringify(model)}');
    window.current_drive_order = ${current_drive_order};
    window.UI = JSON.parse('${JSON.stringify(uiConfig)}');
  </script>
  <script src="https://rawcdn.githack.com/didala083/goindex-extended/refs/heads/master/app.js"></script>
</head>
<body>
</body>
</html>
`;
}

async function apiRequest(request, gd) {
  let url = new URL(request.url);
  let path = url.pathname;
  path = path.replace(gd.url_path_prefix, '') || '/';
  let option = {status: 200, headers: {'Access-Control-Allow-Origin': '*'}};

  if (path.substr(-1) == '/') {
    let form = await request.formData();
    let deferred_list_result = gd.list(path, form.get('page_token'), Number(form.get('page_index')));
    if (gd.authConfig['enable_password_file_verify']) {
      let password = await gd.password(path);
      if (password && password.replace("\n", "") !== form.get('password')) {
        let html = `{"error": {"code": 401,"message": "password error."}}`;
        return new Response(html, option);
      }
    }
    let list_result = await deferred_list_result;
    return new Response(JSON.stringify(list_result), option);
  } else {
    let file = await gd.file(path);
    return new Response(JSON.stringify(file));
  }
}

async function handleSearch(request, gd) {
  const option = {status: 200, headers: {'Access-Control-Allow-Origin': '*'}};
  let form = await request.formData();
  let search_result = await gd.search(form.get('q') || '', form.get('page_token'), Number(form.get('page_index')));
  return new Response(JSON.stringify(search_result), option);
}

async function handleId2Path(request, gd) {
  const option = {status: 200, headers: {'Access-Control-Allow-Origin': '*'}};
  let form = await request.formData();
  let path = await gd.findPathById(form.get('id'));
  return new Response(path || '', option);
}

/**
 * Google Drive API 封装类
 * 功能：处理与Google Drive的交互，包括文件列表、搜索、下载等操作
 */
class googleDrive {
  constructor(authConfig, order) {
    this.order = order;
    this.root = authConfig.roots[order];
    this.root.protect_file_link = this.root.protect_file_link || false;
    this.url_path_prefix = `/${order}:`;
    this.authConfig = authConfig;
    this.paths = [];
    this.files = [];
    this.passwords = [];
    this.id_path_cache = {};
    this.id_path_cache[this.root['id']] = '/';
    this.paths["/"] = this.root['id'];
    this.path_children_cache = {};
  }

  async init() {
    await this.accessToken();
    if (this.authConfig.user_drive_real_root_id) return;
    const root_obj = await (gds[0] || this).findItemById('root');
    if (root_obj && root_obj.id) {
      this.authConfig.user_drive_real_root_id = root_obj.id;
    }
  }

  async initRootType() {
    const root_id = this.root['id'];
    const types = CONSTS.gd_root_type;
    if (root_id === 'root' || root_id === this.authConfig.user_drive_real_root_id) {
      this.root_type = types.user_drive;
    } else {
      const obj = await this.getShareDriveObjById(root_id);
      this.root_type = obj ? types.share_drive : types.sub_folder;
    }
  }

  /**
   * 基本认证检查
   * 用于目录浏览和API请求的认证
   * @param {Request} request - HTTP请求对象
   * @returns {Response|null} 认证失败返回401响应，成功返回null
   */
  basicAuthResponse(request) {
    const user = this.root.user || '',
      pass = this.root.pass || '';
    
    console.log("检查认证:", !!user, !!pass);
      
    // 如果未设置用户名和密码，则不进行认证
    if (!user && !pass) {
      console.log("未设置用户名和密码，跳过认证");
      return null;
    }
    
    const _401 = new Response('Unauthorized', {
      headers: {
        'WWW-Authenticate': 'Basic realm="GoIndex Drive"',
        'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
        'Pragma': 'no-cache'
      },
      status: 401
    });
    
    const auth = request.headers.get('Authorization');
    if (!auth) {
      // 没有提供认证头，返回401要求认证
      console.log('未提供认证头，请求认证');
      return _401; // 确保未提供认证头时总是返回401
    }
    
    try {
      // 解析Basic认证头
      const authValue = auth.split(' ');
      if (authValue.length !== 2 || authValue[0] !== 'Basic') {
        console.log('认证格式无效');
        return _401;
      }
      
      const credentials = atob(authValue[1]);
      console.log("认证凭据格式:", credentials.includes(':'));
      
      if (!credentials.includes(':')) {
        console.log('认证凭据格式无效');
        return _401;
      }
      
      const [received_user, received_pass] = credentials.split(':');
      console.log("接收到的用户名/密码:", !!received_user, !!received_pass);
      
      if (received_user === user && received_pass === pass) {
        // 认证成功
        console.log('认证成功');
        return null;
      } else {
        // 认证失败
        console.log('认证凭据无效');
        return _401;
      }
    } catch (e) {
      console.error('认证错误:', e);
      return _401;
    }
  }

  /**
   * 下载文件内容
   * 注意：此方法无需认证，允许直接访问文件
   * @param {string} id - Google Drive文件ID
   * @param {string} range - HTTP Range头（支持断点续传）
   * @param {boolean} inline - 是否内联显示文件
   * @returns {Response} 文件内容响应
   */
  async down(id, range = '', inline = false) {
    let url = `https://www.googleapis.com/drive/v3/files/${id}?alt=media`;
    let requestOption = await this.requestOption();
    requestOption.headers['Range'] = range;
    let res = await fetch(url, requestOption);
    if (this.authConfig.enable_virus_infected_file_down) {
      if (res.status === 403) {
        url += '&acknowledgeAbuse=true';
        res = await this.fetch200(url, requestOption);
      }
    }
    const {headers} = res = new Response(res.body, res)
    this.authConfig.enable_cors_file_down && headers.append('Access-Control-Allow-Origin', '*');
    inline === true && headers.set('Content-Disposition', 'inline');
    return res;
  }

  async file(path) {
    if (typeof this.files[path] == 'undefined') {
      this.files[path] = await this._file(path);
    }
    return this.files[path];
  }

  async _file(path) {
    let arr = path.split('/');
    let name = arr.pop();
    name = decodeURIComponent(name).replace(/\'/g, "\\'");
    let dir = arr.join('/') + '/';
    let parent = await this.findPathId(dir);
    let url = 'https://www.googleapis.com/drive/v3/files';
    let params = {'includeItemsFromAllDrives': true, 'supportsAllDrives': true};
    params.q = `'${parent}' in parents and name = '${name}' and trashed = false`;
    params.fields = "files(id, name, mimeType, size ,createdTime, modifiedTime, iconLink, thumbnailLink)";
    url += '?' + this.enQuery(params);
    let requestOption = await this.requestOption();
    let response = await fetch(url, requestOption);
    let obj = await response.json();
    return obj.files[0];
  }

  /**
   * 列出目录内容（分页）
   * 需要基本认证
   * @param {string} path - 目录路径
   * @param {string} page_token - 分页令牌
   * @param {number} page_index - 当前页码
   * @returns {Object} 包含文件列表的分页结果
   */
  async list(path, page_token = null, page_index = 0) {
    if (this.path_children_cache == undefined) {
      this.path_children_cache = {};
    }

    if (this.path_children_cache[path]
      && this.path_children_cache[path][page_index]
      && this.path_children_cache[path][page_index].data
    ) {
      let child_obj = this.path_children_cache[path][page_index];
      return {
        nextPageToken: child_obj.nextPageToken || null,
        curPageIndex: page_index,
        data: child_obj.data
      };
    }

    let id = await this.findPathId(path);
    let result = await this._ls(id, page_token, page_index);
    let data = result.data;
    if (result.nextPageToken && data.files) {
      if (!Array.isArray(this.path_children_cache[path])) {
        this.path_children_cache[path] = []
      }
      this.path_children_cache[path][Number(result.curPageIndex)] = {
        nextPageToken: result.nextPageToken,
        data: data
      };
    }

    return result
  }

  async _ls(parent, page_token = null, page_index = 0) {
    if (parent == undefined) {
      return null;
    }
    let obj;
    let params = {'includeItemsFromAllDrives': true, 'supportsAllDrives': true};
    params.q = `'${parent}' in parents and trashed = false AND name !='.password'`;
    params.orderBy = 'folder,name,modifiedTime desc';
    params.fields = "nextPageToken, files(id, name, mimeType, size , modifiedTime)";
    params.pageSize = this.authConfig.files_list_page_size;

    if (page_token) {
      params.pageToken = page_token;
    }
    let url = 'https://www.googleapis.com/drive/v3/files';
    url += '?' + this.enQuery(params);
    let requestOption = await this.requestOption();
    let response = await fetch(url, requestOption);
    obj = await response.json();

    return {
      nextPageToken: obj.nextPageToken || null,
      curPageIndex: page_index,
      data: obj
    };
  }

  async password(path) {
    if (this.passwords[path] !== undefined) {
      return this.passwords[path];
    }

    let file = await this.file(path + '.password');
    if (file == undefined) {
      this.passwords[path] = null;
    } else {
      let url = `https://www.googleapis.com/drive/v3/files/${file.id}?alt=media`;
      let requestOption = await this.requestOption();
      let response = await this.fetch200(url, requestOption);
      this.passwords[path] = await response.text();
    }

    return this.passwords[path];
  }

  async getShareDriveObjById(any_id) {
    if (!any_id) return null;
    if ('string' !== typeof any_id) return null;

    let url = `https://www.googleapis.com/drive/v3/drives/${any_id}`;
    let requestOption = await this.requestOption();
    let res = await fetch(url, requestOption);
    let obj = await res.json();
    if (obj && obj.id) return obj;

    return null
  }

  /**
   * 搜索文件
   * 需要基本认证
   * @param {string} origin_keyword - 原始搜索关键字
   * @param {string} page_token - 分页令牌
   * @param {number} page_index - 当前页码
   * @returns {Object} 包含搜索结果的分页数据
   */
  async search(origin_keyword, page_token = null, page_index = 0) {
    const types = CONSTS.gd_root_type;
    const is_user_drive = this.root_type === types.user_drive;
    const is_share_drive = this.root_type === types.share_drive;

    const empty_result = {
      nextPageToken: null,
      curPageIndex: page_index,
      data: null
    };

    if (!is_user_drive && !is_share_drive) {
      return empty_result;
    }
    let keyword = FUNCS.formatSearchKeyword(origin_keyword);
    if (!keyword) {
      return empty_result;
    }
    let words = keyword.split(/\s+/);
    let name_search_str = `name contains '${words.join("' AND name contains '")}'`;

    let params = {};
    if (is_user_drive) {
      params.corpora = 'user'
    }
    if (is_share_drive) {
      params.corpora = 'drive';
      params.driveId = this.root.id;
      params.includeItemsFromAllDrives = true;
      params.supportsAllDrives = true;
    }
    if (page_token) {
      params.pageToken = page_token;
    }
    params.q = `trashed = false AND name !='.password' AND (${name_search_str})`;
    params.fields = "nextPageToken, files(id, name, mimeType, size , modifiedTime)";
    params.pageSize = this.authConfig.search_result_list_page_size;
    let url = 'https://www.googleapis.com/drive/v3/files';
    url += '?' + this.enQuery(params);
    let requestOption = await this.requestOption();
    let response = await fetch(url, requestOption);
    let res_obj = await response.json();

    return {
      nextPageToken: res_obj.nextPageToken || null,
      curPageIndex: page_index,
      data: res_obj
    };
  }

  async findParentFilesRecursion(child_id, contain_myself = true) {
    const gd = this;
    const gd_root_id = gd.root.id;
    const user_drive_real_root_id = this.authConfig.user_drive_real_root_id;
    const is_user_drive = gd.root_type === CONSTS.gd_root_type.user_drive;

    const target_top_id = is_user_drive ? user_drive_real_root_id : gd_root_id;
    const fields = CONSTS.default_file_fields;

    const parent_files = [];
    let meet_top = false;

    async function addItsFirstParent(file_obj) {
      if (!file_obj) return;
      if (!file_obj.parents) return;
      if (file_obj.parents.length < 1) return;

      let p_ids = file_obj.parents;
      if (p_ids && p_ids.length > 0) {
        const first_p_id = p_ids[0];
        if (first_p_id === target_top_id) {
          meet_top = true;
          return;
        }
        const p_file_obj = await gd.findItemById(first_p_id);
        if (p_file_obj && p_file_obj.id) {
          parent_files.push(p_file_obj);
          await addItsFirstParent(p_file_obj);
        }
      }
    }

    const child_obj = await gd.findItemById(child_id);
    if (contain_myself) {
      parent_files.push(child_obj);
    }
    await addItsFirstParent(child_obj);

    return meet_top ? parent_files : null
  }

  async findPathById(child_id) {
    if (this.id_path_cache[child_id]) {
      return this.id_path_cache[child_id];
    }

    const p_files = await this.findParentFilesRecursion(child_id);
    if (!p_files || p_files.length < 1) return '';

    let cache = [];
    p_files.forEach((value, idx) => {
      const is_folder = idx === 0 ? (p_files[idx].mimeType === CONSTS.folder_mime_type) : true;
      let path = '/' + p_files.slice(idx).map(it => it.name).reverse().join('/');
      if (is_folder) path += '/';
      cache.push({id: p_files[idx].id, path: path})
    });

    cache.forEach((obj) => {
      this.id_path_cache[obj.id] = obj.path;
      this.paths[obj.path] = obj.id
    });

    return cache[0].path;
  }

  async findItemById(id) {
    const is_user_drive = this.root_type === CONSTS.gd_root_type.user_drive;
    let url = `https://www.googleapis.com/drive/v3/files/${id}?fields=${CONSTS.default_file_fields}${is_user_drive ? '' : '&supportsAllDrives=true'}`;
    let requestOption = await this.requestOption();
    let res = await fetch(url, requestOption);
    return await res.json()
  }

  async findPathId(path) {
    let c_path = '/';
    let c_id = this.paths[c_path];

    let arr = path.trim('/').split('/');
    for (let name of arr) {
      c_path += name + '/';

      if (typeof this.paths[c_path] == 'undefined') {
        let id = await this._findDirId(c_id, name);
        this.paths[c_path] = id;
      }

      c_id = this.paths[c_path];
      if (c_id == undefined || c_id == null) {
        break;
      }
    }
    return this.paths[path];
  }

  async _findDirId(parent, name) {
    name = decodeURIComponent(name).replace(/\'/g, "\\'");

    if (parent == undefined) {
      return null;
    }

    let url = 'https://www.googleapis.com/drive/v3/files';
    let params = {'includeItemsFromAllDrives': true, 'supportsAllDrives': true};
    params.q = `'${parent}' in parents and mimeType = 'application/vnd.google-apps.folder' and name = '${name}'  and trashed = false`;
    params.fields = "nextPageToken, files(id, name, mimeType)";
    url += '?' + this.enQuery(params);
    let requestOption = await this.requestOption();
    let response = await fetch(url, requestOption);
    let obj = await response.json();
    
    if (!obj.files[0]) return null
    const same_name = obj.files.find(v => v.name === name)
    if (!same_name) {
        return obj.files[0].id;
    }
    return same_name.id
  }

  async accessToken() {
    console.log("accessToken");
    if (this.authConfig.expires == undefined || this.authConfig.expires < Date.now()) {
      const obj = await this.fetchAccessToken();
      if (obj.access_token != undefined) {
        this.authConfig.accessToken = obj.access_token;
        this.authConfig.expires = Date.now() + 3500 * 1000;
      }
    }
    return this.authConfig.accessToken;
  }

  async fetchAccessToken() {
    console.log("fetchAccessToken");
    const url = "https://www.googleapis.com/oauth2/v4/token";
    const headers = {
      'Content-Type': 'application/x-www-form-urlencoded'
    };
    const post_data = {
      'client_id': this.authConfig.client_id,
      'client_secret': this.authConfig.client_secret,
      'refresh_token': this.authConfig.refresh_token,
      'grant_type': 'refresh_token'
    }

    let requestOption = {
      'method': 'POST',
      'headers': headers,
      'body': this.enQuery(post_data)
    };

    const response = await fetch(url, requestOption);
    return await response.json();
  }

  async fetch200(url, requestOption) {
    let response;
    for (let i = 0; i < 3; i++) {
      response = await fetch(url, requestOption);
      console.log(response.status);
      if (response.status != 403) {
        break;
      }
      await this.sleep(800 * (i + 1));
    }
    return response;
  }

  async requestOption(headers = {}, method = 'GET') {
    const accessToken = await this.accessToken();
    headers['authorization'] = 'Bearer ' + accessToken;
    return {'method': method, 'headers': headers};
  }

  enQuery(data) {
    const ret = [];
    for (let d in data) {
      ret.push(encodeURIComponent(d) + '=' + encodeURIComponent(data[d]));
    }
    return ret.join('&');
  }

  sleep(ms) {
    return new Promise(function (resolve, reject) {
      let i = 0;
      setTimeout(function () {
        console.log('sleep' + ms);
        i++;
        if (i >= 2) reject(new Error('i>=2'));
        else resolve(i);
      }, ms);
    })
  }
}

String.prototype.trim = function (char) {
  if (char) {
    return this.replace(new RegExp('^\\' + char + '+|\\' + char + '+$', 'g'), '');
  }
  return this.replace(/^\s+|\s+$/g, '');
};

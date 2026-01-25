--[[
  Request Tamper Extension for Marshall Browser
  Intercept, modify, and replay HTTP requests for testing
  Written in Lua for scripting flexibility
  Part of Marshall Extensions Collection
]]

local json = require("json")
local marshall = require("marshall")

-- Extension state
local RequestTamper = {
  version = "1.0.0",
  enabled = false,
  intercept_enabled = false,
  rules = {},
  history = {},
  max_history = 500,
  breakpoints = {},
  pending_requests = {}
}

-- Rule types
local RuleType = {
  MODIFY_HEADER = "modify_header",
  ADD_HEADER = "add_header",
  REMOVE_HEADER = "remove_header",
  MODIFY_BODY = "modify_body",
  MODIFY_URL = "modify_url",
  BLOCK = "block",
  DELAY = "delay",
  REDIRECT = "redirect"
}

-- Match conditions
local MatchType = {
  CONTAINS = "contains",
  EQUALS = "equals",
  REGEX = "regex",
  STARTS_WITH = "starts_with",
  ENDS_WITH = "ends_with"
}

--[[
  Initialize the extension
]]
function RequestTamper:init()
  -- Load saved rules
  local saved_rules = marshall.storage.get("tamper_rules")
  if saved_rules then
    self.rules = json.decode(saved_rules)
  end
  
  -- Load saved breakpoints
  local saved_breakpoints = marshall.storage.get("breakpoints")
  if saved_breakpoints then
    self.breakpoints = json.decode(saved_breakpoints)
  end
  
  -- Register request interceptor
  marshall.webRequest.onBeforeRequest(function(details)
    return self:handleRequest(details)
  end, { urls = {"<all_urls>"} })
  
  -- Register header interceptor
  marshall.webRequest.onBeforeSendHeaders(function(details)
    return self:handleHeaders(details)
  end, { urls = {"<all_urls>"} })
  
  -- Register response interceptor
  marshall.webRequest.onHeadersReceived(function(details)
    return self:handleResponse(details)
  end, { urls = {"<all_urls>"} })
  
  -- Register toolbar button
  marshall.toolbar.register({
    id = "request-tamper",
    icon = "🔧",
    title = "Request Tamper",
    onclick = function() self:showPanel() end
  })
  
  -- Register keyboard shortcut
  marshall.keyboard.register("Ctrl+Shift+T", function()
    self:toggleIntercept()
  end)
  
  print("[Request Tamper] Initialized")
  self.enabled = true
end

--[[
  Check if URL matches a pattern
]]
function RequestTamper:matchUrl(url, pattern, match_type)
  match_type = match_type or MatchType.CONTAINS
  
  if match_type == MatchType.CONTAINS then
    return string.find(url, pattern, 1, true) ~= nil
  elseif match_type == MatchType.EQUALS then
    return url == pattern
  elseif match_type == MatchType.REGEX then
    return string.match(url, pattern) ~= nil
  elseif match_type == MatchType.STARTS_WITH then
    return string.sub(url, 1, #pattern) == pattern
  elseif match_type == MatchType.ENDS_WITH then
    return string.sub(url, -#pattern) == pattern
  end
  
  return false
end

--[[
  Handle incoming request
]]
function RequestTamper:handleRequest(details)
  local request_id = details.requestId
  local url = details.url
  local method = details.method
  
  -- Add to history
  self:addToHistory({
    id = request_id,
    timestamp = os.time(),
    url = url,
    method = method,
    type = details.type,
    initiator = details.initiator or ""
  })
  
  -- Check for breakpoint
  if self.intercept_enabled then
    for _, bp in ipairs(self.breakpoints) do
      if bp.enabled and self:matchUrl(url, bp.pattern, bp.match_type) then
        -- Pause and wait for user action
        return self:pauseRequest(details)
      end
    end
  end
  
  -- Apply matching rules
  for _, rule in ipairs(self.rules) do
    if rule.enabled and self:matchUrl(url, rule.pattern, rule.match_type) then
      local result = self:applyRule(rule, details)
      if result then
        return result
      end
    end
  end
  
  return {}
end

--[[
  Handle request headers
]]
function RequestTamper:handleHeaders(details)
  local url = details.url
  local headers = details.requestHeaders or {}
  local modified = false
  
  for _, rule in ipairs(self.rules) do
    if rule.enabled and self:matchUrl(url, rule.pattern, rule.match_type) then
      if rule.type == RuleType.MODIFY_HEADER then
        for i, header in ipairs(headers) do
          if string.lower(header.name) == string.lower(rule.header_name) then
            headers[i].value = rule.header_value
            modified = true
          end
        end
      elseif rule.type == RuleType.ADD_HEADER then
        table.insert(headers, {
          name = rule.header_name,
          value = rule.header_value
        })
        modified = true
      elseif rule.type == RuleType.REMOVE_HEADER then
        for i = #headers, 1, -1 do
          if string.lower(headers[i].name) == string.lower(rule.header_name) then
            table.remove(headers, i)
            modified = true
          end
        end
      end
    end
  end
  
  if modified then
    return { requestHeaders = headers }
  end
  
  return {}
end

--[[
  Handle response
]]
function RequestTamper:handleResponse(details)
  local url = details.url
  local headers = details.responseHeaders or {}
  
  -- Update history with response info
  for i = #self.history, 1, -1 do
    if self.history[i].id == details.requestId then
      self.history[i].status = details.statusCode
      self.history[i].response_headers = headers
      break
    end
  end
  
  return {}
end

--[[
  Apply a tamper rule
]]
function RequestTamper:applyRule(rule, details)
  if rule.type == RuleType.BLOCK then
    print(string.format("[Request Tamper] Blocked: %s", details.url))
    return { cancel = true }
    
  elseif rule.type == RuleType.REDIRECT then
    print(string.format("[Request Tamper] Redirect: %s -> %s", details.url, rule.redirect_url))
    return { redirectUrl = rule.redirect_url }
    
  elseif rule.type == RuleType.DELAY then
    -- Note: In real implementation, this would use async
    print(string.format("[Request Tamper] Delay %dms: %s", rule.delay_ms, details.url))
    -- Delay would be handled by sandbox
    
  elseif rule.type == RuleType.MODIFY_URL then
    local new_url = string.gsub(details.url, rule.url_pattern, rule.url_replacement)
    if new_url ~= details.url then
      print(string.format("[Request Tamper] URL Modified: %s -> %s", details.url, new_url))
      return { redirectUrl = new_url }
    end
  end
  
  return nil
end

--[[
  Pause request for manual inspection
]]
function RequestTamper:pauseRequest(details)
  local request_id = details.requestId
  
  -- Store pending request
  self.pending_requests[request_id] = {
    details = details,
    paused_at = os.time()
  }
  
  -- Show notification
  marshall.ui.notify(
    string.format("Request paused: %s %s", details.method, details.url),
    "warning"
  )
  
  -- Show intercept panel
  self:showInterceptPanel(details)
  
  -- Wait for user action (handled by async in real implementation)
  -- Return cancel for now
  return { cancel = true }
end

--[[
  Add request to history
]]
function RequestTamper:addToHistory(entry)
  table.insert(self.history, 1, entry)
  
  -- Trim history
  while #self.history > self.max_history do
    table.remove(self.history)
  end
end

--[[
  Add a new rule
]]
function RequestTamper:addRule(rule)
  rule.id = tostring(os.time()) .. "-" .. math.random(1000, 9999)
  rule.enabled = true
  rule.created = os.time()
  
  table.insert(self.rules, rule)
  self:saveRules()
  
  return rule.id
end

--[[
  Remove a rule
]]
function RequestTamper:removeRule(rule_id)
  for i, rule in ipairs(self.rules) do
    if rule.id == rule_id then
      table.remove(self.rules, i)
      self:saveRules()
      return true
    end
  end
  return false
end

--[[
  Toggle rule enabled state
]]
function RequestTamper:toggleRule(rule_id)
  for _, rule in ipairs(self.rules) do
    if rule.id == rule_id then
      rule.enabled = not rule.enabled
      self:saveRules()
      return rule.enabled
    end
  end
  return nil
end

--[[
  Add breakpoint
]]
function RequestTamper:addBreakpoint(pattern, match_type)
  local bp = {
    id = tostring(os.time()) .. "-" .. math.random(1000, 9999),
    pattern = pattern,
    match_type = match_type or MatchType.CONTAINS,
    enabled = true
  }
  
  table.insert(self.breakpoints, bp)
  self:saveBreakpoints()
  
  return bp.id
end

--[[
  Toggle intercept mode
]]
function RequestTamper:toggleIntercept()
  self.intercept_enabled = not self.intercept_enabled
  
  marshall.ui.notify(
    self.intercept_enabled and "Intercept enabled" or "Intercept disabled",
    "info"
  )
  
  -- Update toolbar badge
  if self.intercept_enabled then
    marshall.toolbar.setBadge("request-tamper", "●")
  else
    marshall.toolbar.setBadge("request-tamper", "")
  end
end

--[[
  Save rules to storage
]]
function RequestTamper:saveRules()
  marshall.storage.set("tamper_rules", json.encode(self.rules))
end

--[[
  Save breakpoints to storage
]]
function RequestTamper:saveBreakpoints()
  marshall.storage.set("breakpoints", json.encode(self.breakpoints))
end

--[[
  Replay a request from history
]]
function RequestTamper:replayRequest(history_id)
  local entry = nil
  for _, h in ipairs(self.history) do
    if h.id == history_id then
      entry = h
      break
    end
  end
  
  if not entry then
    return false
  end
  
  -- Make request through sandbox
  marshall.network.fetch(entry.url, {
    method = entry.method,
    headers = entry.request_headers
  })
  
  return true
end

--[[
  Export history as HAR
]]
function RequestTamper:exportHAR()
  local har = {
    log = {
      version = "1.2",
      creator = {
        name = "Marshall Request Tamper",
        version = self.version
      },
      entries = {}
    }
  }
  
  for _, h in ipairs(self.history) do
    local entry = {
      startedDateTime = os.date("!%Y-%m-%dT%H:%M:%SZ", h.timestamp),
      request = {
        method = h.method,
        url = h.url,
        httpVersion = "HTTP/1.1"
      },
      response = {
        status = h.status or 0,
        statusText = ""
      }
    }
    table.insert(har.log.entries, entry)
  end
  
  return json.encode(har)
end

--[[
  Show main panel
]]
function RequestTamper:showPanel()
  local html = self:generatePanelHTML()
  marshall.ui.showPanel(html, {
    title = "Request Tamper",
    width = 700,
    height = 600
  })
end

--[[
  Generate panel HTML
]]
function RequestTamper:generatePanelHTML()
  local rules_html = ""
  for _, rule in ipairs(self.rules) do
    rules_html = rules_html .. string.format([[
      <tr class="%s">
        <td><input type="checkbox" %s onchange="tamper.toggleRule('%s')"></td>
        <td>%s</td>
        <td>%s</td>
        <td>%s</td>
        <td>
          <button onclick="tamper.editRule('%s')">Edit</button>
          <button onclick="tamper.removeRule('%s')">Delete</button>
        </td>
      </tr>
    ]], rule.enabled and "" or "disabled",
        rule.enabled and "checked" or "",
        rule.id, rule.type, rule.pattern, rule.description or "",
        rule.id, rule.id)
  end
  
  local history_html = ""
  for i = 1, math.min(20, #self.history) do
    local h = self.history[i]
    history_html = history_html .. string.format([[
      <tr>
        <td>%s</td>
        <td>%s</td>
        <td class="url">%s</td>
        <td class="status-%d">%d</td>
        <td>
          <button onclick="tamper.replayRequest('%s')">↻</button>
          <button onclick="tamper.inspectRequest('%s')">🔍</button>
        </td>
      </tr>
    ]], h.method, os.date("%H:%M:%S", h.timestamp),
        string.sub(h.url, 1, 60), 
        math.floor((h.status or 0) / 100),
        h.status or 0, h.id, h.id)
  end
  
  return string.format([[
    <div class="tamper-panel">
      <div class="toolbar">
        <button class="%s" onclick="tamper.toggleIntercept()">
          %s Intercept
        </button>
        <button onclick="tamper.addRuleDialog()">+ Add Rule</button>
        <button onclick="tamper.addBreakpointDialog()">+ Breakpoint</button>
        <button onclick="tamper.exportHAR()">Export HAR</button>
      </div>
      
      <div class="tabs">
        <button class="active" data-tab="rules">Rules</button>
        <button data-tab="history">History</button>
        <button data-tab="breakpoints">Breakpoints</button>
      </div>
      
      <div class="tab-content" id="rules-tab">
        <h3>Tamper Rules</h3>
        <table class="rules-table">
          <thead>
            <tr>
              <th>On</th>
              <th>Type</th>
              <th>Pattern</th>
              <th>Description</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            %s
          </tbody>
        </table>
      </div>
      
      <div class="tab-content hidden" id="history-tab">
        <h3>Request History</h3>
        <table class="history-table">
          <thead>
            <tr>
              <th>Method</th>
              <th>Time</th>
              <th>URL</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            %s
          </tbody>
        </table>
      </div>
    </div>
  ]], self.intercept_enabled and "active" or "",
      self.intercept_enabled and "🔴 Disable" or "🟢 Enable",
      rules_html, history_html)
end

--[[
  Show intercept panel for paused request
]]
function RequestTamper:showInterceptPanel(details)
  local html = string.format([[
    <div class="intercept-panel">
      <h2>🛑 Request Intercepted</h2>
      
      <div class="request-info">
        <p><strong>Method:</strong> %s</p>
        <p><strong>URL:</strong> %s</p>
        <p><strong>Type:</strong> %s</p>
      </div>
      
      <div class="request-editor">
        <h3>Headers</h3>
        <textarea id="request-headers">%s</textarea>
        
        <h3>Body</h3>
        <textarea id="request-body">%s</textarea>
      </div>
      
      <div class="intercept-actions">
        <button class="primary" onclick="tamper.forwardRequest('%s')">Forward</button>
        <button onclick="tamper.forwardModified('%s')">Forward Modified</button>
        <button class="danger" onclick="tamper.dropRequest('%s')">Drop</button>
      </div>
    </div>
  ]], details.method, details.url, details.type,
      json.encode(details.requestHeaders or {}),
      details.requestBody or "",
      details.requestId, details.requestId, details.requestId)
  
  marshall.ui.showPanel(html, {
    title = "Intercept",
    width = 600,
    height = 500
  })
end

-- Extension entry point
marshall.extension.onActivate(function()
  RequestTamper:init()
end)

marshall.extension.onDeactivate(function()
  print("[Request Tamper] Deactivated")
end)

-- Export API
marshall.extension.export("addRule", function(rule) return RequestTamper:addRule(rule) end)
marshall.extension.export("removeRule", function(id) return RequestTamper:removeRule(id) end)
marshall.extension.export("getHistory", function() return RequestTamper.history end)
marshall.extension.export("replay", function(id) return RequestTamper:replayRequest(id) end)

return RequestTamper

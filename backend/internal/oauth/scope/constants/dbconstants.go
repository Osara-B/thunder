/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

// Package constants defines constants related to OAuth scopes.
package constants

import dbmodel "github.com/asgardeo/thunder/internal/system/database/model"

// QueryGetAuthorizedScopesByClientID is the query to retrieve authorized scopes by client ID.
var QueryGetAuthorizedScopesByClientID = dbmodel.DBQuery{
	ID: "SCQ-00001",
	Query: "SELECT s.NAME FROM AUTHORIZED_SCOPE as ascope JOIN SCOPE as s ON ascope.SCOPE_ID = s.UUID " +
		"JOIN IDN_OAUTH_CONSUMER_APPS as apps ON ascope.APP_ID = apps.APP_ID WHERE apps.CONSUMER_KEY = $1",
}

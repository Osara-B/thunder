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

// Package store provides the implementation for IdP persistence operations.
package store

import dbmodel "github.com/asgardeo/thunder/internal/system/database/model"

var (
	// QueryCreateIdP is the query to create a new IdP.
	QueryCreateIdP = dbmodel.DBQuery{
		ID: "IPQ-IDP_MGT-01",
		Query: "INSERT INTO \"IDP\" (IDP_ID, NAME, DESCRIPTION, CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, SCOPES) " +
			"VALUES ($1, $2, $3, $4, $5, $6, $7)",
	}

	// QueryGetIdPByIdPID is the query to get a IdP by IdP ID.
	QueryGetIdPByIdPID = dbmodel.DBQuery{
		ID: "IPQ-IDP_MGT-02",
		Query: "SELECT IDP_ID, NAME, DESCRIPTION, CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, SCOPES FROM \"IDP\" " +
			"WHERE IDP_ID = $1",
	}
	// QueryGetIdPList is the query to get a list of IdPs.
	QueryGetIdPList = dbmodel.DBQuery{
		ID:    "IPQ-IDP_MGT-03",
		Query: "SELECT IDP_ID, NAME, DESCRIPTION, CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, SCOPES FROM \"IDP\"",
	}
	// QueryUpdateIdPByIdPID is the query to update a IdP by IdP ID.
	QueryUpdateIdPByIdPID = dbmodel.DBQuery{
		ID: "IPQ-IDP_MGT-04",
		Query: "UPDATE \"IDP\" SET NAME = $2, DESCRIPTION = $3, CLIENT_ID = $4, CLIENT_SECRET = $5, " +
			"REDIRECT_URI = $6, SCOPES = $7 WHERE IDP_ID = $1;",
	}
	// QueryDeleteIdPByIdPID is the query to delete a IdP by IdP ID.
	QueryDeleteIdPByIdPID = dbmodel.DBQuery{
		ID:    "IPQ-IDP_MGT-05",
		Query: "DELETE FROM \"IDP\" WHERE IDP_ID = $1",
	}
)

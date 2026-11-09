// Copyright (C) 2026 Shirofune Security Co., Ltd.

// SPDX-License-Identifier: RPL-1.5 OR AGPL-3.0-only
//
// You may alternatively use this file under the GNU Affero General Public License,
// version 3 only; see LICENSE-AGPL-3.0. The following notice applies to the RPL option.
//
// Unless explicitly acquired and licensed from Licensor under another license, the contents of this
// file are subject to the Reciprocal Public License ("RPL") Version 1.5, or subsequent versions as
// allowed by the RPL, and You may not copy or use this file in either source code or executable
// form, except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS" basis, WITHOUT WARRANTY
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing rights
// and limitations under the RPL.

//! Cross-platform read-only NTFS image access. FUSE mounting additionally requires Linux.

pub mod image;
#[cfg(target_os = "linux")]
pub mod image_mount;

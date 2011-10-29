//
//  extract.h
//  KindleTool
//
//  Created by Yifan Lu on 10/28/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#ifndef KINDLETOOL_EXTRACT
#define KINDLETOOL_EXTRACT

#include "kindle_tool.h"

BundleVersion get_bundle_version(char*);
int read_bundle_header(UpdateHeader *, FILE *);
int extract(FILE *, FILE *, FILE *);
int extract_ota_update_v2(FILE *, FILE *);
int extract_signature(FILE *, FILE *);
int extract_ota_update(FILE *, FILE *);
int extract_recovery(FILE *, FILE *);

#endif

// version.h
//
// Version information for vscpl2drv-socketcan.
//
// Copyright (c) 2000-2026 Ake Hedman and contributors, the VSCP Project
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

// Version is YEAR.MONTH.PATCH
// PATCH is bumped automatically on every push to master by CI
// (see tools/bump_version.sh and .github/workflows/build.yml).
// It is reset to zero when year/month changes.

#define MAJOR_VERSION       2026
#define MINOR_VERSION       10
#define PATCH_VERSION       3

#define DISPLAY_VERSION "2026.10.3"
#define COPYRIGHT       "Copyright (c) 2000-2026 Ake Hedman and contributors, the VSCP Project"
#define COPYRIGHT_HTML  "Copyright (c) 2000-2026 Ake Hedman and contributors, the VSCP Project"
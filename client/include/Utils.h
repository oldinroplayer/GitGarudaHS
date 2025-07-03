#pragma once
#include <string>
#include <algorithm>

inline bool ContainsIgnoreCase(const std::wstring& hay, const std::wstring& needle) {
    std::wstring lo = hay, nd = needle;
    std::transform(lo.begin(), lo.end(), lo.begin(), ::towlower);
    std::transform(nd.begin(), nd.end(), nd.begin(), ::towlower);
    return lo.find(nd) != std::wstring::npos;
}
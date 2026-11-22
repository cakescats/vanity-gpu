#include "report.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <ctime>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

volatile std::sig_atomic_t g_stop = 0;

Reporter::Reporter(const PatternSet& ps, std::string path, bool show_keys, uint64_t want, bool quiet)
    : Reporter(std::vector<const PatternSet*>{&ps}, std::move(path), show_keys, want, quiet) {}

Reporter::Reporter(std::vector<const PatternSet*> sets, std::string path, bool show_keys, uint64_t want, bool quiet)
    : sets_(std::move(sets)), path_(std::move(path)), show_keys_(show_keys), quiet_(quiet), want_(want) {
  double log_miss = 0;
  for (const PatternSet* p : sets_) {
    log_miss += std::log1p(-std::min(p->p_match, 0.999999));
    per_chain_.push_back({p->chain, 0});
  }
  p_match_ = -std::expm1(log_miss);
}

uint64_t Reporter::found_count(Chain c) const {
  for (auto& pc : per_chain_)
    if (pc.first == c) return pc.second;
  return 0;
}

std::string Reporter::label() const {
  std::string s;
  for (const PatternSet* p : sets_) s += (s.empty() ? "" : "+") + std::string(chain_name(p->chain));
  return s;
}

static std::string fmt_duration(double s) {
  if (!std::isfinite(s) || s > 1e12) return "∞";
  char b[64];
  if (s < 60) snprintf(b, sizeof b, "%.0fs", s);
  else if (s < 3600) snprintf(b, sizeof b, "%.0fm%02.0fs", floor(s / 60), fmod(s, 60));
  else if (s < 86400 * 2) snprintf(b, sizeof b, "%.0fh%02.0fm", floor(s / 3600), fmod(s / 60, 60));
  else if (s < 86400 * 365 * 2) snprintf(b, sizeof b, "%.1f days", s / 86400);
  else snprintf(b, sizeof b, "%.3g years", s / (86400 * 365.25));
  return b;
}

static std::string fmt_count(double v) {
  char b[32];
  const char* u[] = {"", "K", "M", "G", "T", "P", "E"};
  int i = 0;
  while (v >= 1000 && i < 6) { v /= 1000; i++; }
  snprintf(b, sizeof b, "%.2f %s", v, u[i]);
  return b;
}

void Reporter::found(Chain chain, const std::string& address, const std::string& what, const KV& info,
                     const KV& secret) {
  found_++;
  for (auto& pc : per_chain_)
    if (pc.first == chain) pc.second++;
  addresses_.push_back(address);
  if (!path_.empty()) {
    int fd = open(path_.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) {
      perror(path_.c_str());
    } else {
      fchmod(fd, 0600);
      char ts[32];
      time_t t = time(nullptr);
      strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", localtime(&t));
      std::string s = std::string("# ") + ts + "  " + chain_name(chain) + "  " + what + "\n";
      s += "address = " + address + "\n";
      for (auto& kv : info) s += kv.first + " = " + kv.second + "\n";
      for (auto& kv : secret) s += kv.first + " = " + kv.second + "\n";
      s += "\n";
      if (write(fd, s.data(), s.size()) != (ssize_t)s.size()) perror("write");
      fsync(fd);
      close(fd);
    }
  }
  if (quiet_) return;
  fprintf(stderr, "\r\033[K");
  if (sets_.size() > 1) printf("[+] %-10s %s   (%s)\n", chain_name(chain), address.c_str(), what.c_str());
  else printf("[+] %s   (%s)\n", address.c_str(), what.c_str());
  for (auto& kv : info) printf("    %s: %s\n", kv.first.c_str(), kv.second.c_str());
  if (show_keys_)
    for (auto& kv : secret) printf("    %s: %s\n", kv.first.c_str(), kv.second.c_str());
  else if (!secret.empty() && !path_.empty())
    printf("    private key saved to %s\n", path_.c_str());
  fflush(stdout);
}

void Reporter::reject(const std::string& why) {
  rejected_++;
  if (rejected_ <= 5) fprintf(stderr, "\r\033[K[!] GPU candidate failed CPU verification: %s\n", why.c_str());
}

void Reporter::dropped(uint64_t n) {
  if (!dropped_warned_ && !quiet_)
    fprintf(stderr, "\r\033[K[!] more than %d matches in one GPU batch; %llu were skipped. "
                    "Use a longer pattern or a higher --min-score.\n",
            MAX_HITS, (unsigned long long)n);
  dropped_warned_ = true;
}

void Reporter::progress(double keys, double secs, bool final_line, const std::string& note) {
  if (quiet_) return;
  double rate = secs > 0 ? keys / secs : 0;
  std::string eta;
  if (p_match_ > 0 && rate > 0) {
    double expect = 1.0 / p_match_;  // mean keys per hit
    double p_now = -std::expm1(-keys * p_match_);
    eta = " | 50%: " + fmt_duration(std::log(2.0) * expect / rate) + " | luck " +
          std::to_string((int)std::round(p_now * 100)) + "%";
  }
  std::string found = std::to_string(found_);
  if (per_chain_.size() > 1 && found_) {
    std::string parts;
    for (auto& pc : per_chain_)
      if (pc.second) parts += (parts.empty() ? "" : " ") + std::string(chain_name(pc.first)) + ":" + std::to_string(pc.second);
    found += " (" + parts + ")";
  }
  fprintf(stderr, "\r\033[K[%s] %skey/s%s | %skeys | %s | found %s%s", label().c_str(),
          fmt_count(rate).c_str(), note.empty() ? "" : (" (" + note + ")").c_str(), fmt_count(keys).c_str(),
          fmt_duration(secs).c_str(), found.c_str(), eta.c_str());
  if (final_line) fprintf(stderr, "\n");
  fflush(stderr);
}

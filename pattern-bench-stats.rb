#!/usr/bin/env ruby

abort "usage: #{$0} a1 a2 ... an b1 b2 ... bn" unless ARGV.length.even?

n = ARGV.length / 2
a_files = ARGV.take(n)
b_files = ARGV.drop(n)

LINE_RE = /
  ^
  (\d+)\s+            # matches
  \((\d+)\)\s+        # checks
  (\d+(?:\.\d+)?)ms\s+\|\s+
  [+\-!]\s+sh\s+
  (.+?)\s+->          # shell pattern
/x
TOTAL_RE = /time: (\d+(?:\.\d+)?)ms/

def load_suite(files)
  stats = Hash.new { |h, k| h[k] = { matches: [], checks: [], time: [] } }
  total_time = []
  setup_time = []

  files.each do |path|
    last_lines = [nil, nil]
    File.foreach(path) do |line|
      last_lines << line
      last_lines.shift
      m = LINE_RE.match(line) or next
      matches, checks, time, pat = m.captures
      s = stats[pat]
      s[:matches] << matches.to_i
      s[:checks]  << checks.to_i
      s[:time]    << time.to_f
    end
    total_time << last_lines[0][TOTAL_RE, 1].to_f
    setup_time << last_lines[1][TOTAL_RE, 1].to_f
  end

  [stats, total_time, setup_time]
end

a, a_time, a_setuptime = load_suite(a_files)
b, b_time, b_setuptime = load_suite(b_files)

def mean(arr)
  arr.sum.to_f / arr.size
end

def stddev(arr)
  mean = mean(arr)
  mean(arr.map { (it - mean).abs })**0.5
end

puts [
  "",
  "#checks",
  "a_ms_avg",
  "b_ms_avg",
  "Δms",
  "Δ%"
].join("\t")

a.keys.each do |k|
  sa = a[k]
  sb = b[k]

  a_ms = sa[:time]
  b_ms = sb[:time]

  a_avg = mean(a_ms)
  b_avg = mean(b_ms)
  a_stddev = stddev(a_ms)
  b_stddev = stddev(b_ms)

  puts [
    k,
    (sa[:checks] + sb[:checks]).min,
    "#{a_avg.round(2)} (𝜎#{a_stddev.round(1)})",
    "#{b_avg.round(2)} (𝜎#{b_stddev.round(1)})",
    (b_avg - a_avg).round(2),
    "#{-(100 - (b_avg / a_avg * 100)).round}%"
  ].join("\t")
end

puts

a_time_avg = mean(a_time)
b_time_avg = mean(b_time)
a_time_stddev = stddev(a_time)
b_time_stddev = stddev(b_time)
puts "Total time\t\t#{a_time_avg.round(2)} (𝜎#{a_time_stddev.round(1)})\t#{b_time_avg.round(2)} (𝜎#{b_time_stddev.round(1)})\t#{(b_time_avg - a_time_avg).round(2)}\t#{-(100 - (b_time_avg / a_time_avg * 100)).round}%"

a_setuptime_avg = mean(a_setuptime)
b_setuptime_avg = mean(b_setuptime)
a_setuptime_stddev = stddev(a_setuptime)
b_setuptime_stddev = stddev(b_setuptime)
puts "Setup time\t\t#{a_setuptime_avg.round(2)} (𝜎#{a_setuptime_stddev.round(1)})\t#{b_setuptime_avg.round(2)} (𝜎#{b_setuptime_stddev.round(1)})\t#{(b_setuptime_avg - a_setuptime_avg).round(2)}\t#{-(100 - (b_setuptime_avg / a_setuptime_avg * 100)).round}%"

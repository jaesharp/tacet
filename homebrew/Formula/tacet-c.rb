class TacetC < Formula
  desc "C/C++ bindings for tacet timing oracle library"
  homepage "https://github.com/agucova/tacet"
  version "0.4.2"
  license "MPL-2.0"

  if Hardware::CPU.arm?
    url "https://github.com/agucova/tacet/releases/download/v#{version}/libtacet_c-darwin-arm64.a"
    sha256 "abc71e600a512ff4ef4c3b0db93c9dee60946ca52ce5ae8f6669c28fe910c5f8"
  else
    url "https://github.com/agucova/tacet/releases/download/v#{version}/libtacet_c-darwin-amd64.a"
    sha256 "878a65e0eebbe304c5b9dc708fa248e5d1f3faaf5e44ccaf5feae1fd4b0f5b3f"
  end

  # Resources for additional files needed
  resource "tacet.h" do
    url "https://github.com/agucova/tacet/releases/download/v#{version}/tacet.h"
    sha256 "5f979b23d99f6c5ddb6f522797c95fb40c3a0f1242a3573f1d639bea89323ffe"
  end

  resource "tacet.hpp" do
    url "https://github.com/agucova/tacet/releases/download/v#{version}/tacet.hpp"
    sha256 "638a085f5bb0172cf740a5f606760da11fc501643194f952fefe1ff1ec9e31f6"
  end

  def install
    # The main URL downloads the static library
    if Hardware::CPU.arm?
      lib.install "libtacet_c-darwin-arm64.a" => "libtacet_c.a"
    else
      lib.install "libtacet_c-darwin-amd64.a" => "libtacet_c.a"
    end

    # Download and install headers
    resource("tacet.h").stage do
      (include/"tacet").install "tacet.h"
    end

    resource("tacet.hpp").stage do
      (include/"tacet").install "tacet.hpp"
    end

    # Generate pkg-config file
    (lib/"pkgconfig").mkpath
    (lib/"pkgconfig/tacet.pc").write <<~EOS
      prefix=#{prefix}
      exec_prefix=${prefix}
      libdir=#{lib}
      includedir=#{include}

      Name: tacet
      Description: Statistical timing side-channel detection library
      Version: #{version}
      URL: https://github.com/agucova/tacet
      Libs: -L${libdir} -ltacet_c -framework Security -framework CoreFoundation
      Cflags: -I${includedir}
    EOS
  end

  test do
    # Test pkg-config
    assert_match version.to_s, shell_output("pkg-config --modversion tacet")
    assert_match "-ltacet_c", shell_output("pkg-config --libs tacet")
    assert_match "-I#{include}/tacet", shell_output("pkg-config --cflags tacet")

    # Test C compilation
    (testpath/"test.c").write <<~EOS
      #include <tacet/tacet.h>
      #include <stdio.h>

      int main() {
          const char* version = to_version();
          printf("tacet version: %s\\n", version);

          ToConfig cfg = to_config_adjacent_network();
          printf("threshold: %.1f ns\\n", to_attacker_threshold_ns(cfg.attacker_model));

          return 0;
      }
    EOS

    system ENV.cc, "test.c", "-o", "test",
           "-I#{include}/tacet", "-L#{lib}", "-ltacet_c",
           "-framework", "Security", "-framework", "CoreFoundation"

    system "./test"

    # Test C++ compilation
    (testpath/"test.cpp").write <<~EOS
      #include <tacet/tacet.hpp>
      #include <iostream>
      #include <chrono>
      using namespace std::chrono_literals;

      int main() {
          std::cout << "tacet C++ wrapper test" << std::endl;

          auto oracle = tacet::Oracle::forAttacker(ToAttackerModel::AdjacentNetwork)
              .timeBudget(10s);

          return 0;
      }
    EOS

    system ENV.cxx, "-std=c++20", "test.cpp", "-o", "test_cpp",
           "-I#{include}/tacet", "-L#{lib}", "-ltacet_c",
           "-framework", "Security", "-framework", "CoreFoundation"

    system "./test_cpp"
  end
end

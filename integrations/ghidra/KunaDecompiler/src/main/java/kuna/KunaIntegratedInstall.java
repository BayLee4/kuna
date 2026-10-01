/* kuna — isolated Ghidra integration with the authentic p-code producer.
 * Apache-2.0. kuna is derived from Ghidra (https://github.com/NationalSecurityAgency/ghidra).
 */
package kuna;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.jar.Attributes;
import java.util.jar.JarFile;

/** Creates a private Ghidra distribution; never modifies the supplied installation. */
public final class KunaIntegratedInstall {
	private static final String MODEL =
		"Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar";
	private static final String SOURCES =
		"Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling-src.zip";
	private static final String DECOMPILER =
		"Ghidra/Features/Decompiler/lib/Decompiler.jar";
	private static final String DECOMPILER_SOURCES =
		"Ghidra/Features/Decompiler/lib/Decompiler-src.zip";
	private static final String APPLICATION = "Ghidra/application.properties";
	private static final String EMITTER = "ghidra/app/plugin/processors/sleigh/PcodeEmit";

	private KunaIntegratedInstall() {
	}

	public static void main(String[] args) throws Exception {
		if (args.length != 2) {
			throw new IllegalArgumentException(
				"Usage: java -cp <extension>/lib/KunaDecompiler.jar " +
					"kuna.KunaIntegratedInstall <Ghidra installation> <new output directory>");
		}
		Path source = Path.of(args[0]).toRealPath();
		Path requested = Path.of(args[1]).toAbsolutePath().normalize();
		Path destination = requested.getParent().toRealPath().resolve(requested.getFileName());
		if (Files.exists(destination, LinkOption.NOFOLLOW_LINKS) || destination.startsWith(source)) {
			throw new IOException("Output must be a new directory outside the source installation: " +
				destination);
		}
		Path extension = Path.of(KunaIntegratedInstall.class.getProtectionDomain()
			.getCodeSource().getLocation().toURI()).toRealPath().getParent().getParent();
		Path producer = extension.resolve("producer/kuna-ghidra-producer.jar");
		verifyProducer(source, producer);
		checkExistingPatches(source.resolve("Ghidra/patch"));

		// Follow links while copying so no output subtree can mutate the source installation.
		// In particular, do not symlink the bootstrap jars: Ghidra resolves their real paths.
		copyTree(source, destination, source.resolve("Ghidra/Extensions/KunaDecompiler"));
		copyTree(extension, destination.resolve("Ghidra/Extensions/KunaDecompiler"), null);
		Path patch = destination.resolve("Ghidra/patch/kuna-ghidra-producer.jar");
		Files.createDirectories(patch.getParent());
		Files.copy(producer, patch, StandardCopyOption.COPY_ATTRIBUTES);
		System.out.println("Integrated Ghidra installation: " + destination);
		System.out.println("Launch its ghidraRun (or ghidraRun.bat), enable KunaDecompilerPlugin, " +
			"and use its support/analyzeHeadless for headless analysis.");
		System.out.println("For PyGhidra set GHIDRA_INSTALL_DIR=" + destination);
		System.out.println("The original Ghidra installation was not modified.");
	}

	private static void verifyProducer(Path source, Path producer) throws IOException {
		try (JarFile jar = new JarFile(producer.toFile())) {
			if (jar.getManifest() == null) {
				throw new IOException("Producer JAR has no build manifest: " + producer);
			}
			Attributes attributes = jar.getManifest().getMainAttributes();
			if (!"callreturn-v1".equals(attributes.getValue("Kuna-Producer-Protocol"))) {
				throw new IOException("Unsupported Kuna producer protocol: " + producer);
			}
			verifyHash(source.resolve(APPLICATION), attributes, "Ghidra-Application-SHA256");
			verifyHash(source.resolve(MODEL), attributes, "Ghidra-SoftwareModeling-SHA256");
			verifyHash(source.resolve(SOURCES), attributes, "Ghidra-Source-SHA256");
			if (!"2-e4030-4039-a4030-4048".equals(attributes.getValue("Kuna-Callable-Support-Protocol"))) {
				throw new IOException("Unsupported Kuna callable support protocol: " + producer);
			}
			verifyHash(source.resolve(DECOMPILER), attributes, "Ghidra-Decompiler-SHA256");
			verifyHash(source.resolve(DECOMPILER_SOURCES), attributes, "Ghidra-Decompiler-Source-SHA256");
		}
	}

	private static void verifyHash(Path file, Attributes attributes, String key) throws IOException {
		MessageDigest digest;
		try {
			digest = MessageDigest.getInstance("SHA-256");
		}
		catch (NoSuchAlgorithmException e) {
			throw new AssertionError(e);
		}
		try (InputStream input = Files.newInputStream(file)) {
			byte[] buffer = new byte[65536];
			int length;
			while ((length = input.read(buffer)) != -1) {
				digest.update(buffer, 0, length);
			}
		}
		if (!HexFormat.of().formatHex(digest.digest()).equals(attributes.getValue(key))) {
			throw new IOException("Producer was built for a different Ghidra distribution: " +
				file + ". Rebuild the extension against this installation.");
		}
	}

	private static void checkExistingPatches(Path patchDirectory) throws IOException {
		if (!Files.isDirectory(patchDirectory)) {
			return;
		}
		try (var files = Files.walk(patchDirectory)) {
			for (Path file : files.filter(Files::isRegularFile).toList()) {
				String relative = patchDirectory.relativize(file).toString().replace('\\', '/');
				if (isProducerClass(relative)) {
					throw new IOException("Source installation already overrides the producer: " + file);
				}
				if (file.getFileName().toString().endsWith(".jar")) {
					try (JarFile jar = new JarFile(file.toFile())) {
						if (jar.stream().anyMatch(entry -> isProducerClass(entry.getName()))) {
							throw new IOException("Source installation already overrides the producer: " + file);
						}
					}
				}
			}
		}
	}

	private static boolean isProducerClass(String name) {
		return name.equals(EMITTER + ".class") || name.equals(EMITTER + "Packed.class") ||
			name.startsWith(EMITTER + "Packed$") ||
			isClass(name, "ghidra/program/model/pcode/PcodeDataTypeManager") ||
			isClass(name, "ghidra/program/model/data/DataTypeWriter") ||
			isClass(name, "ghidra/app/decompiler/DecompileResults") ||
			isClass(name, "ghidra/app/decompiler/DecompiledFunction") ||
			isClass(name, "ghidra/app/decompiler/CallableSupport") ||
			isClass(name, "ghidra/app/util/exporter/CppExporter");
	}

	private static boolean isClass(String name, String base) {
		return name.equals(base + ".class") || name.startsWith(base + "$");
	}

	private static void copyTree(Path source, Path destination, Path excluded) throws IOException {
		Files.walkFileTree(source, EnumSet.of(FileVisitOption.FOLLOW_LINKS), Integer.MAX_VALUE,
			new SimpleFileVisitor<Path>() {
				@Override
				public FileVisitResult preVisitDirectory(Path directory, BasicFileAttributes attrs)
						throws IOException {
					if (directory.equals(excluded)) {
						return FileVisitResult.SKIP_SUBTREE;
					}
					Files.createDirectories(destination.resolve(source.relativize(directory)));
					return FileVisitResult.CONTINUE;
				}

				@Override
				public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
					Files.copy(file, destination.resolve(source.relativize(file)),
						StandardCopyOption.COPY_ATTRIBUTES);
					return FileVisitResult.CONTINUE;
				}
			});
	}
}

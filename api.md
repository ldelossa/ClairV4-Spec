# API

This section of the spec provide API schema declarations. 
Schemas will be provided in Golang struct syntax. 
Note json tags marked "-" are not included in JSON marshalling.

## Distribution
    // Distribution is the accompanying system context of a package. this
    // information aides in CVE detection. scanners should identify this information before
    // starting their scan and tag each found package with as much as this discovered info as possible.
    type Distribution struct {
        // unique ID of this distribution. this will be created as discovered by the library
        // and used for persistence and hash map indexes.
        ID int `json:"id"`
        // A lower-case string (no spaces or other characters outside of 0–9, a–z, ".", "_" and "-") identifying the operating system, excluding any version information
        // and suitable for processing by scripts or usage in generated filenames. Example: "DID=fedora" or "DID=debian".
        DID string `json:"did"`
        // A string identifying the operating system.
        // example: "Ubuntu"
        Name string `json:"name"`
        // A string identifying the operating system version, excluding any OS name information,
        // possibly including a release code name, and suitable for presentation to the user.
        // example: "16.04.6 LTS (Xenial Xerus)"
        Version string `json:"version"`
        // A lower-case string (no spaces or other characters outside of 0–9, a–z, ".", "_" and "-") identifying the operating system release code name,
        // excluding any OS name information or release version, and suitable for processing by scripts or usage in generated filenames
        // example: "xenial"
        VersionCodeName string `json:"version_code_name"`
        // A lower-case string (mostly numeric, no spaces or other characters outside of 0–9, a–z, ".", "_" and "-")
        // identifying the operating system version, excluding any OS name information or release code name,
        // example: "16.04"
        VersionID string `json:"version_id"`
        // A string identifying the OS architecture
        // example: "x86_64"
        Arch string `json:"arch"`
        // Optional common platform enumeration identifier
        CPE string `json:"cpe"`
        // A pretty operating system name in a format suitable for presentation to the user.
        // May or may not contain a release code name or OS version of some kind, as suitable. If not set, defaults to "PRETTY_NAME="Linux"".
        // example: "PRETTY_NAME="Fedora 17 (Beefy Miracle)"".
        PrettyName string `json:"pretty_name"`
    }


## Layer
    // RemotePath provides http retrieval information about a layer.
    type RemotePath struct {
        URI     string              `json:"uri"`
        Headers map[string][]string `json:"headers"`
    }

    // Layer is an containers image filesystem layer. Layers are stacked
    // ontop of each other to comprise the final filesystem of the container image.
    type Layer struct {
        // content addressable hash unequally identifying this layer. libindex will treat layers with this same
        // hash as identical.
        Hash string `json:"hash"`
        // format of the archived layer. currently we support tar with Gzip, Bzip2, and Xz compression. compression
        // format will be determined via moby library.
        Format string `json:"format"`
        // the format of this image. typically this is the container technology which created the image.
        ImageFormat string `json:"image_format"`
        // uncompressed tar archive of the layer's content read into memory
        Bytes []byte `json:"-"`
        // path to local file containing uncompressed tar archive of the layer's content
        LocalPath string `json:"-"`
        // the URI and header information for retrieving a layer via http
        RemotePath RemotePath `json:"remote_path"`
    }

## Package 
    type Package struct {
        // unique ID of this package. this will be created as discovered by the library
        // and used for persistence and hash map indexes
        ID int `json:"id"`
        // the name of the distribution
        Name string `json:"name"`
        // the version of the distribution
        Version string `json:"version"`
        // type of package. currently expectations are binary or source
        Kind string `json:"kind"`
        // if type is a binary package a source package maybe present which built this binary package.
        // must be a pointer to support recursive type:
        Source *Package `json:"source"`
        // the file system path or prefix where this package resides
        PackageDB string `json:"package_db"`
        // a hint on which repository this package was downloaded from
        RepositoryHint string `json:"repository_hint"`
    }

## Repository
    // Repository is a package repository
    type Repository struct {
        ID   int    `json:"id"`
        Name string `json:"name"`
        Key  string `json:"key"`
        URI  string `json:"uri"`
    }

## Vulnerability
    type Vulnerability struct {
        // unique ID of this vulnerability. this will be created as discovered by the library
        // and used for persistence and hash map indexes
        ID int `json:"id"`
        // the updater that discovered this vulnerability
        Updater string `json:"updater"`
        // the name of the vulnerability. for example if the vulnerability exists in a CVE database this
        // would the unique CVE name such as CVE-2017-11722
        Name string `json:"name"`
        // the description of the vulnerability
        Description string `json:"description"`
        // any links to more details about the vulnerability
        Links string `json:"links"`
        // the severity of the vulnerability
        Severity string `json:"severity"`
        // the package information associated with the vulnerability. ideally these fields can be matched
        // to packages discovered by libindex PackageScanner structs.
        Package *Package `json:"package"`
        // the distribution information associated with the vulnerability.
        Dist *Distribution `json:"dist"`
        // the repository information associated with the vulnerability
        Repo *Repository `json:"repo"`
        // a string specifying the package version the fix was relased in
        FixedInVersion string `json:"fixed_in_version"`
    }


## IndexReport/IndexRecord
    // IndexRecord is an entry in the IndexReport.
    //
    // A IndexRecord identifies a discovered package along with its
    // Distribution and Repository information if present.
    type IndexRecord struct {
        Package      *Package
        Distribution *Distribution
        Repository   *Repository
    }

    // IndexReport provides a package database for a container image.
    //
    // A IndexReport is used to inventory a discrete package information found
    // within in each layer of a container image.
    type IndexReport struct {
        // the manifest hash this scan result is assocaited with
        Hash string `json:"manifest_hash"`
        // the current state of the scan.
        State string `json:"state"`
        // packages found after applying all layers
        Packages map[int]*Package `json:"packages"`
        // distributions found after applying all layers
        Distributions map[int]*Distribution `json:"distributions"`
        // repositories found after applying all layers
        Repositories map[int]*Repository `json:"repository"`
        // PackagesByDistribution maps a package id to it's associated distribution id
        DistributionByPackage map[int]int `json:"distribution_by_package"`
        // PackagesByRepositories maps a package id to it's associated repository id
        RepositoryByPackage map[int]int `json:"repository_by_package"`
        // layer hash that introduced the given package id
        PackageIntroduced map[int]string `json:"package_introduced"`
        // whether the scan was successful
        Success bool `json:"success"`
        // the first fatal error that occured during a scan process
        Err string `json:"err"`
    }

## VulnerabilityReport/Details
type Details struct {
	// the package details which matched the associated vulnerability
	AffectedPackage Package `json:"affected_package"`
	// the layer hash within the image the package was introduced
	IntroducedIn string `json:"introduced_in"`
	// the version in which the package no longer is affected by the associated
	// vulnerability
	FixedInVersion string `json:"fixed_in_version"`
}

type VulnerabilityReport struct {
	// manifest hash this vulnerability report is describing
	Hash string `json:"manifest_hash"`
	// found vulnerabilities key'd by ids
	Vulnerabilities map[int]*Vulnerability `json:"vulnerabilities"`
	// details explaining affected packages. key'd by vulnerability id
	Details map[int][]Details `json:"details"`
}



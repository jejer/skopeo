package registry

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/containers/image/v5/directory/explicitfilepath"
	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/internal/image"
	"github.com/containers/image/v5/transports"
	"github.com/containers/image/v5/types"
	"github.com/opencontainers/go-digest"
)

func init() {
	transports.Register(Transport)
}

// Transport is an ImageTransport for directory paths.
var Transport = registryTransport{}

type registryTransport struct{}

func (t registryTransport) Name() string {
	return "registry-dir"
}

// ParseReference converts a string, which should not start with the ImageTransport.Name prefix, into an ImageReference.
func (t registryTransport) ParseReference(reference string) (types.ImageReference, error) {
	return NewReference(reference)
}

// ValidatePolicyConfigurationScope checks that scope is a valid name for a signature.PolicyTransportScopes keys
// (i.e. a valid PolicyConfigurationIdentity() or PolicyConfigurationNamespaces() return value).
// It is acceptable to allow an invalid value which will never be matched, it can "only" cause user confusion.
// scope passed to this function will not be "", that value is always allowed.
func (t registryTransport) ValidatePolicyConfigurationScope(scope string) error {
	if !strings.HasPrefix(scope, "/") {
		return fmt.Errorf("Invalid scope %s: Must be an absolute path", scope)
	}
	// Refuse also "/", otherwise "/" and "" would have the same semantics,
	// and "" could be unexpectedly shadowed by the "/" entry.
	if scope == "/" {
		return errors.New(`Invalid scope "/": Use the generic default scope ""`)
	}
	cleaned := filepath.Clean(scope)
	if cleaned != scope {
		return fmt.Errorf(`Invalid scope %s: Uses non-canonical format, perhaps try %s`, scope, cleaned)
	}
	return nil
}

// registryReference is an ImageReference for directory paths.
type registryReference struct {
	// Note that the interpretation of paths below depends on the underlying filesystem state, which may change under us at any time!
	// Either of the paths may point to a different, or no, inode over time.  resolvedPath may contain symbolic links, and so on.

	// Generally we follow the intent of the user, and use the "path" member for filesystem operations (e.g. the user can use a relative path to avoid
	// being exposed to symlinks and renames in the parent directories to the working directory).
	// (But in general, we make no attempt to be completely safe against concurrent hostile filesystem modifications.)
	path         string // As specified by the user. May be relative, contain symlinks, etc.
	resolvedPath string // Absolute path with no symlinks, at least at the time of its creation. Primarily used for policy namespaces.

	repo string
	tag  string
}

// There is no directory.ParseReference because it is rather pointless.
// Callers who need a transport-independent interface will go through
// registryTransport.ParseReference; callers who intentionally deal with directories
// can use directory.NewReference.

// NewReference returns a directory reference for a specified path.
//
// We do not expose an API supplying the resolvedPath; we could, but recomputing it
// is generally cheap enough that we prefer being confident about the properties of resolvedPath.
func NewReference(refString string) (types.ImageReference, error) {
	parts := strings.Split(refString, ":")
	if len(parts) != 3 {
		return nil, fmt.Errorf(`Invalid path %s: format should be path:repo:tag`, refString)
	}
	path := parts[0]
	resolved, err := explicitfilepath.ResolvePathToFullyExplicit(path)
	if err != nil {
		return nil, err
	}
	return registryReference{path: path, resolvedPath: resolved, repo: parts[1], tag: parts[2]}, nil
}

func (ref registryReference) Transport() types.ImageTransport {
	return Transport
}

// StringWithinTransport returns a string representation of the reference, which MUST be such that
// reference.Transport().ParseReference(reference.StringWithinTransport()) returns an equivalent reference.
// NOTE: The returned string is not promised to be equal to the original input to ParseReference;
// e.g. default attribute values omitted by the user may be filled in in the return value, or vice versa.
// WARNING: Do not use the return value in the UI to describe an image, it does not contain the Transport().Name() prefix.
func (ref registryReference) StringWithinTransport() string {
	return fmt.Sprintf("%s:%s:%s", ref.path, ref.repo, ref.tag)
}

// DockerReference returns a Docker reference associated with this reference
// (fully explicit, i.e. !reference.IsNameOnly, but reflecting user intent,
// not e.g. after redirect or alias processing), or nil if unknown/not applicable.
func (ref registryReference) DockerReference() reference.Named {
	return nil
}

// PolicyConfigurationIdentity returns a string representation of the reference, suitable for policy lookup.
// This MUST reflect user intent, not e.g. after processing of third-party redirects or aliases;
// The value SHOULD be fully explicit about its semantics, with no hidden defaults, AND canonical
// (i.e. various references with exactly the same semantics should return the same configuration identity)
// It is fine for the return value to be equal to StringWithinTransport(), and it is desirable but
// not required/guaranteed that it will be a valid input to Transport().ParseReference().
// Returns "" if configuration identities for these references are not supported.
func (ref registryReference) PolicyConfigurationIdentity() string {
	return ref.resolvedPath
}

// PolicyConfigurationNamespaces returns a list of other policy configuration namespaces to search
// for if explicit configuration for PolicyConfigurationIdentity() is not set.  The list will be processed
// in order, terminating on first match, and an implicit "" is always checked at the end.
// It is STRONGLY recommended for the first element, if any, to be a prefix of PolicyConfigurationIdentity(),
// and each following element to be a prefix of the element preceding it.
func (ref registryReference) PolicyConfigurationNamespaces() []string {
	res := []string{}
	path := ref.resolvedPath
	for {
		lastSlash := strings.LastIndex(path, "/")
		if lastSlash == -1 || lastSlash == 0 {
			break
		}
		path = path[:lastSlash]
		res = append(res, path)
	}
	// Note that we do not include "/"; it is redundant with the default "" global default,
	// and rejected by registryTransport.ValidatePolicyConfigurationScope above.
	return res
}

// NewImage returns a types.ImageCloser for this reference, possibly specialized for this ImageTransport.
// The caller must call .Close() on the returned ImageCloser.
// NOTE: If any kind of signature verification should happen, build an UnparsedImage from the value returned by NewImageSource,
// verify that UnparsedImage, and convert it into a real Image via image.FromUnparsedImage.
// WARNING: This may not do the right thing for a manifest list, see image.FromSource for details.
func (ref registryReference) NewImage(ctx context.Context, sys *types.SystemContext) (types.ImageCloser, error) {
	return image.FromReference(ctx, sys, ref)
}

// NewImageSource returns a types.ImageSource for this reference.
// The caller must call .Close() on the returned ImageSource.
func (ref registryReference) NewImageSource(ctx context.Context, sys *types.SystemContext) (types.ImageSource, error) {
	return newImageSource(ref), nil
}

// NewImageDestination returns a types.ImageDestination for this reference.
// The caller must call .Close() on the returned ImageDestination.
func (ref registryReference) NewImageDestination(ctx context.Context, sys *types.SystemContext) (types.ImageDestination, error) {
	return nil, errors.New("NewImageDestination images not implemented for registry-dir: images")
}

// DeleteImage deletes the named image from the registry, if supported.
func (ref registryReference) DeleteImage(ctx context.Context, sys *types.SystemContext) error {
	return errors.New("Deleting images not implemented for dir: images")
}

// manifestPath returns a path for the manifest within a directory using our conventions.
func (ref registryReference) manifestPath(instanceDigest *digest.Digest) (string, error) {
	if instanceDigest == nil {
		link := filepath.Join(ref.resolvedPath, "docker/registry/v2/repositories", ref.repo, "_manifests/tags", ref.tag, "current/link")
		content, err := os.ReadFile(link)
		if err != nil {
			return "", fmt.Errorf(`Manifest link %s: read error`, link)
		}

		digest, err := digest.Parse(string(content))
		if err != nil {
			return "", err
		}
		instanceDigest = &digest
	}

	path := filepath.Join(ref.resolvedPath, "docker/registry/v2/blobs/sha256", instanceDigest.Encoded()[:2], instanceDigest.Encoded(), "data")
	return path, nil
}

// layerPath returns a path for a layer tarball within a directory using our conventions.
func (ref registryReference) layerPath(digest digest.Digest) string {
	return filepath.Join(ref.resolvedPath, "docker/registry/v2/blobs/sha256", digest.Encoded()[:2], digest.Encoded(), "data")
}

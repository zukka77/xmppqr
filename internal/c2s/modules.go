package c2s

import (
	"github.com/danielinux/xmppqr/internal/block"
	"github.com/danielinux/xmppqr/internal/bookmarks"
	"github.com/danielinux/xmppqr/internal/caps"
	"github.com/danielinux/xmppqr/internal/carbons"
	"github.com/danielinux/xmppqr/internal/disco"
	"github.com/danielinux/xmppqr/internal/httpupload"
	"github.com/danielinux/xmppqr/internal/ibr"
	"github.com/danielinux/xmppqr/internal/mam"
	"github.com/danielinux/xmppqr/internal/metrics"
	"github.com/danielinux/xmppqr/internal/muc"
	"github.com/danielinux/xmppqr/internal/pep"
	"github.com/danielinux/xmppqr/internal/presence"
	"github.com/danielinux/xmppqr/internal/pubsub"
	"github.com/danielinux/xmppqr/internal/push"
	"github.com/danielinux/xmppqr/internal/roster"
	"github.com/danielinux/xmppqr/internal/x3dhpq"
	"github.com/danielinux/xmppqr/internal/vcard"
)

type Modules struct {
	Disco      *disco.Features
	Roster     *roster.Manager
	Presence   *presence.Broadcaster
	VCard      *vcard.Manager
	Bookmarks  *bookmarks.Manager
	Block      *block.Manager
	MAM        *mam.Service
	Carbons    *carbons.Manager
	Push       *push.Dispatcher
	HTTPUpload *httpupload.Service
	PubSub     *pubsub.Service
	PEP        *pep.Service
	MUC        *muc.Service
	Metrics    *metrics.Metrics
	X3DHPQPolicy x3dhpq.DomainPolicy
	X3DHPQVerify *x3dhpq.VerifyDevice
	X3DHPQPairLimiter *x3dhpq.PairLimiter
	Caps       *caps.Cache
	IBR        *ibr.Service
}

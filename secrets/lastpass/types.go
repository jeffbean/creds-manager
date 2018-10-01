package lastpass

// https://github.com/lastpass/lastpass-cli/blob/df182dd7c04715f1b18f5ff3a8074e198fc1d06c/blob.h
// struct account {
// 	char *id;
// 	char *name, *name_encrypted;
// 	char *group, *group_encrypted;
// 	char *fullname;
// 	char *url;
// 	char *username, *username_encrypted;
// 	char *password, *password_encrypted;
// 	char *note, *note_encrypted;
// 	char *last_touch, *last_modified_gmt;
// 	bool pwprotect;
// 	bool fav;
// 	bool is_app;
// 	char *attachkey, *attachkey_encrypted;
// 	bool attachpresent;
// 	size_t attach_len;
// 	char *attach_bytes;
//
// 	struct list_head field_head;
// 	struct share *share;
//
// 	struct list_head attach_head;
//
// 	struct list_head list;
// 	struct list_head match_list;
// };

// Account is the more strongly typed struct for a LastPass account object
type Account struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
	URL      string `json:"url"`
	Group    string `json:"group"`
	Notes    string `json:"notes"`
}
